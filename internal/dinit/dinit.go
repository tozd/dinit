// We call maybeSetExitCode(exitDinitFailure) early on an error and do not leave for error to first propagate
// and then set it, so that during cleanup while the error is propagating we do not set some other exit code first.
//
// We cannot use kcmp to compare file descriptors.
// See: https://github.com/moby/moby/issues/45621
//
// We cannot use pidfd_getfd to move file descriptors between processes.
// See: https://github.com/moby/moby/issues/45622
//
// We do not use waitpid(-1, ...) or a similar call which would indiscriminately wait on any subprocess
// because that interferes with any other wait syscall by the same process. Because we care both about
// running and terminated reparented processes (and not just terminated, i.e., zombie processes) we
// cannot rely on SIGCHLD anyway to be informed about new reparented processes, so we do not use
// SIGCHLD + waitpid(-1, ...) but instead poll /proc/1/task/1/children at a regular interval which gives
// us pids of zombie processes as well and we can reap them explicitly by the pid.
// See: https://github.com/golang/go/issues/60481

package dinit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gitlab.com/tozd/go/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"gitlab.com/tozd/dinit/internal/pcontrol"
)

const defaultDir = "/etc/service"

// We check for new reparented processes at a regular interval and trigger configured
// reparenting policy on them. Reparenting also happens on SIGCHLD signal so interval
// between reparenting checks can be shorter.
const reparentingInterval = time.Second

// When dinit is terminating (the context is canceled) we increase the rate at which we
// check for new reparented processes. By default docker stop waits for 10 seconds
// before it kills processes if container does not exit, so we want to detect any
// reparenting which might happen during shutdown and have time to send those processes
// SIGTERM as well. This can happen multiple times if terminating the first wave of
// reparented processes trigger another wave. So keep this under one second or so.
// This is also approximately the time reparenting function waits before returning
// after there is no more known running children.
const reparentingTerminatingInterval = reparentingInterval / 10

// How long to wait after SIGTERM to send SIGKILL to a reparented process?
var reparentingKillTimeout = 30 * time.Second //nolint:gochecknoglobals

const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

const (
	exitSuccess      = 0
	exitDinitFailure = 1
	// 2 is used when Golang runtime fails due to an unrecovered panic or an unexpected runtime condition.
	exitServiceFailure = 3
)

// If run file finishes with code 115 it signals that the program is disabling itself and
// that it does not have to run and the rest of the whole container is then not terminated
// as it would otherwise be when any of its programs finishes.
const serviceExitDisable = 115

const (
	procStatOffset    = 3
	procStatState     = 3
	procStatStartTime = 22
)

var procStatRegexp = regexp.MustCompile(`\((.*)\) (.+)`)

var _SC_CLK_TCK = getClockTicks() //nolint:revive,stylecheck,gochecknoglobals

const matureProcessAge = 10 * time.Millisecond

const waitForDone = 10 * time.Millisecond

// We manually prefix logging.
const logFlags = 0

type policyFunc = func(ctx context.Context, g *errgroup.Group, pid int, waiting chan<- struct{}) errors.E

var debugLog = false //nolint:gochecknoglobals

func timestamp() string {
	return time.Now().UTC().Format(RFC3339Milli)
}

var logDebug = func(msg any) { //nolint:unused,gochecknoglobals
	log.Printf(timestamp()+" dinit: debug: %s", msg)
}

var logDebugf = func(msg string, args ...any) { //nolint:gochecknoglobals
	log.Printf(timestamp()+" dinit: debug: "+msg, args...)
}

var logInfo = func(msg any) { //nolint:unused,gochecknoglobals
	log.Printf(timestamp()+" dinit: info: %s", msg)
}

var logInfof = func(msg string, args ...any) { //nolint:gochecknoglobals
	log.Printf(timestamp()+" dinit: info: "+msg, args...)
}

var logWarn = func(msg any) { //nolint:gochecknoglobals
	log.Printf(timestamp()+" dinit: warning: %s", msg)
}

var logWarnf = func(msg string, args ...any) { //nolint:gochecknoglobals
	log.Printf(timestamp()+" dinit: warning: "+msg, args...)
}

var logError = func(msg any) { //nolint:unused,gochecknoglobals
	log.Printf(timestamp()+" dinit: error: %s", msg)
}

var logErrorf = func(msg string, args ...any) { //nolint:gochecknoglobals
	log.Printf(timestamp()+" dinit: error: "+msg, args...)
}

func processNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) || errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone)
}

var MainContext, MainCancel = context.WithCancel(context.Background()) //nolint:revive,gochecknoglobals

var mainPid = os.Getpid() //nolint:gochecknoglobals

var (
	exitCode   *int       //nolint:gochecknoglobals
	exitCodeMu sync.Mutex //nolint:gochecknoglobals
)

func callers() []uintptr {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:]) //nolint:gomnd
	return pcs[0:n]
}

func maybeSetExitCode(code int, err errors.E) {
	exitCodeMu.Lock()
	defer exitCodeMu.Unlock()
	if exitCode == nil {
		exitCode = &code
	}
	if debugLog && code == exitDinitFailure {
		st := errors.StackFormatter{Stack: callers()}
		if err != nil {
			logDebugf("setting exit code to %d at (most recent call first):\n%+v\ncaused by the following error:\n\n% -+#.1v", code, st, err)
		} else {
			logDebugf("setting exit code to %d at (most recent call first):\n%+v", code, st)
		}
	}
}

func getExitCode() int {
	exitCodeMu.Lock()
	defer exitCodeMu.Unlock()
	if exitCode != nil {
		return *exitCode
	}
	return 0
}

var StdOutLog = log.New(os.Stdout, "", logFlags) //nolint:gochecknoglobals

func Main() {
	ConfigureLog(os.Getenv("DINIT_LOG_LEVEL"))

	killTimeout := os.Getenv("DINIT_KILL_TIMEOUT")
	if killTimeout != "" {
		t, err := strconv.ParseInt(killTimeout, 0, 64)
		if err != nil {
			logErrorf("invalid kill timeout %s", killTimeout)
			os.Exit(exitDinitFailure)
		}
		reparentingKillTimeout = time.Duration(t * int64(time.Second))
	}

	if pid := mainPid; pid != 1 {
		logInfof("not running as a PID 1, but PID %d, registering as a process subreaper", pid)
		// We are not running as PID 1 so we register ourselves as a process subreaper.
		_, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_CHILD_SUBREAPER, 1, 0)
		if errno != 0 {
			logErrorf("exiting: %s", errno)
			os.Exit(exitDinitFailure)
		}
	}

	go handleTerminateSignals()

	g, ctx := errgroup.WithContext(MainContext)

	switch policy := os.Getenv("DINIT_REPARENTING_POLICY"); policy {
	case "adopt":
		g.Go(func() error {
			return reparenting(ctx, g, ReparentingAdopt)
		})
	case "terminate", "": // Default reparenting policy.
		g.Go(func() error {
			return reparenting(ctx, g, ReparentingTerminate)
		})
	case "ignore":
	default:
		logErrorf("invalid reparenting policy %s", policy)
		// We haven't yet used the errgroup, so we can just exit.
		os.Exit(exitDinitFailure)
	}

	g.Go(func() error {
		dir := os.Getenv("DINIT_DIR")
		if dir == "" {
			dir = defaultDir
		}
		return RunServices(ctx, g, dir)
	})

	// The assertion here is that once runServices and reparenting goroutines return
	// (and any they additionally created while running), no more goroutines will be
	// added to the g errgroup.
	err := errors.WithStack(g.Wait())
	if err != nil && !errors.Is(err, context.Canceled) {
		maybeSetExitCode(exitDinitFailure, nil)
		if debugLog {
			logErrorf("exiting: % -+#.1v", err)
		} else {
			logErrorf("exiting: %s", err)
		}
	}

	status := getExitCode()
	logInfof("dinit exiting with status %d", status)
	os.Exit(status)
}

func ConfigureLog(level string) {
	log.SetFlags(logFlags)

	switch level {
	case "none":
		logError = func(msg any) {}
		logErrorf = func(msg string, args ...any) {}
		fallthrough
	case "error":
		logWarn = func(msg any) {}
		logWarnf = func(msg string, args ...any) {}
		fallthrough
	case "warn", "": // Default log level.
		logInfo = func(msg any) {}
		logInfof = func(msg string, args ...any) {}
		fallthrough
	case "info":
		logDebug = func(msg any) {}
		logDebugf = func(msg string, args ...any) {}
	case "debug":
		debugLog = true
	default:
		logErrorf("invalid log level %s", level)
		os.Exit(exitDinitFailure)
	}
}

func handleTerminateSignals() {
	// We do not handle SIGQUIT because that is handled specially by Go runtime.
	c := make(chan os.Signal, 2) //nolint:gomnd
	signal.Notify(c, unix.SIGTERM, unix.SIGINT)
	for s := range c {
		if MainContext.Err() != nil {
			logInfof("got signal %d, already terminating services", s)
		} else {
			logInfof("got signal %d, terminating services", s)
			// Even if children complain being terminated, we still exit with 0.
			maybeSetExitCode(exitSuccess, nil)
			MainCancel()
		}
	}
}

// A counter of all known running sub-processes. We have to make sure we do not call
// errgroup's Add after its Wait has already stopped waiting. We do this by making sure
// reparenting function only returns once the context is canceled and there are no more
// known running children.
var knownRunningChildren = atomic.Int32{} //nolint:gochecknoglobals

// A map of running sub-processes we started or adopted.
var (
	runningChildren   = map[int]bool{} //nolint:gochecknoglobals
	runningChildrenMu sync.RWMutex     //nolint:gochecknoglobals
)

func setRunningChildPid(pid int, lock bool) {
	if lock {
		runningChildrenMu.Lock()
		defer runningChildrenMu.Unlock()
	}
	if runningChildren[pid] {
		panic(errors.New("setting running child PID which already exists"))
	}
	runningChildren[pid] = true
}

func removeRunningChildPid(pid int) {
	runningChildrenMu.Lock()
	defer runningChildrenMu.Unlock()
	if !runningChildren[pid] {
		panic(errors.New("removing running child PID which does not exist"))
	}
	delete(runningChildren, pid)
}

func hasRunningChildPid(pid int) bool {
	runningChildrenMu.RLock()
	defer runningChildrenMu.RUnlock()
	return runningChildren[pid]
}

// We have to wrap every cmd.Start with the runningChildrenMu mutex so that we do not check for the
// running child pid in reparenting while we are starting a new command. Otherwise we might start processing
// a new child process in reparenting before cmd.Start returns (but after the process is already created)
// and before we set the running child pid. If this function returns without an error, a caller should
// call removeRunningChildPid when the process finishes.
func cmdRun(cmd *exec.Cmd) errors.E {
	runningChildrenMu.Lock()
	defer runningChildrenMu.Unlock()

	err := errors.WithStack(cmd.Start())

	if err == nil {
		setRunningChildPid(cmd.Process.Pid, false)
	}

	return err
}

func RunServices(ctx context.Context, g *errgroup.Group, dir string) errors.E {
	entries, e := os.ReadDir(dir)
	if e != nil {
		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		// We skip entries which start with dot.
		if strings.HasPrefix(name, ".") {
			continue
		}
		p := path.Join(dir, name)
		info, e := os.Stat(p)
		if e != nil {
			err := errors.WithStack(e)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
		// We skip anything which is not a directory.
		if !info.IsDir() {
			continue
		}
		knownRunningChildren.Add(1)
		g.Go(func() error {
			defer knownRunningChildren.Add(-1)

			return runService(ctx, g, name, p)
		})
		found = true
	}
	if !found {
		logWarn("no services found, exiting")
		MainCancel()
	}
	return nil
}

func RedirectToLogWithPrefix(l *log.Logger, stage, name, input string, reader io.ReadCloser) {
	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	res := true
	for res {
		res = scanner.Scan()
		line := scanner.Text()
		if len(line) > 0 {
			l.Printf("%s %s/%s: %s\n", timestamp(), name, stage, line)
		}
	}

	e := scanner.Err()
	// Reader can get closed and we ignore that.
	if e != nil && !errors.Is(e, os.ErrClosed) {
		if debugLog {
			logWarnf("%s/%s: error reading %s: % -+#.1v", name, stage, input, e)
		} else {
			logWarnf("%s/%s: error reading %s: %s", name, stage, input, e)
		}
	}
}

func redirectStderrWithPrefix(stage, name string, reader io.ReadCloser) {
	RedirectToLogWithPrefix(log.Default(), stage, name, "stderr", reader)
}

func redirectStdoutWithPrefix(stage, name string, reader io.ReadCloser) {
	RedirectToLogWithPrefix(StdOutLog, stage, name, "stdout", reader)
}

func RedirectJSON(stage, name string, jsonName []byte, reader io.ReadCloser, writer io.Writer) {
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	timeBuffer := make([]byte, 0, len(RFC3339Milli))

	res := true
	for res {
		res = scanner.Scan()
		line := scanner.Bytes()
		if len(line) > 0 {
			// We do a quick check if the line looks like JSON.
			if line[0] == '{' && line[len(line)-1] == '}' {
				now := time.Now().UTC()
				timeBuffer = timeBuffer[:0]
				var buffer bytes.Buffer
				buffer.Write(line[:len(line)-1])
				buffer.WriteString(`,"service":`)
				buffer.Write(jsonName)
				buffer.WriteString(`,"stage":"`)
				buffer.WriteString(stage)
				buffer.WriteString(`","logged":"`)
				buffer.Write(now.AppendFormat(timeBuffer, RFC3339Milli))
				buffer.WriteString(`"}`)
				buffer.WriteString("\n")
				_, e := writer.Write(buffer.Bytes())
				if e != nil {
					if debugLog {
						logWarnf("%s/%s: error writing stdout: % -+#.1v", name, stage, e)
					} else {
						logWarnf("%s/%s: error writing stdout: %s", name, stage, e)
					}
				}
			} else {
				logWarnf("%s/%s: not JSON stdout: %s\n", name, stage, line)
			}
		}
	}

	e := scanner.Err()
	// Reader can get closed and we ignore that.
	if e != nil && !errors.Is(e, os.ErrClosed) {
		if debugLog {
			logWarnf("%s/%s: error reading stdout: % -+#.1v", name, stage, e)
		} else {
			logWarnf("%s/%s: error reading stdout: %s", name, stage, e)
		}
	}
}

func doRedirectAndWait(
	ctx context.Context, pid int, wait func() (*os.ProcessState, errors.E), status *syscall.WaitStatus,
	stage, name string, jsonName []byte, stdout, stderr *os.File,
) errors.E {
	// We do not care about context because we want logging redirects to operate
	// as long as stdout and stderr are open. This could be longer than the process
	// is running because they could be further inherited (or duplicated)
	// by other processes made by the first process. These goroutines close
	// given stdout and stderr readers once they are done with them.
	if stderr != nil {
		go redirectStderrWithPrefix(stage, name, stderr)
	}
	if stdout != nil {
		if os.Getenv("DINIT_JSON_STDOUT") == "0" {
			go redirectStdoutWithPrefix(stage, name, stdout)
		} else {
			go RedirectJSON(stage, name, jsonName, stdout, os.Stdout)
		}
	}

	state, err := wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// If we are here, process finished successfully but the context has been canceled so err was set, so we just ignore the err.
			*status = state.Sys().(syscall.WaitStatus) //nolint:errcheck,forcetypeassert
		} else if state != nil && !state.Success() {
			// This is a condition in Wait when err is set when process fails, so we just ignore the err.
			*status = state.Sys().(syscall.WaitStatus) //nolint:errcheck,forcetypeassert
		} else {
			err = errors.WithMessagef(err, "%s/%s: error waiting for the process", name, stage)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
	} else {
		*status = state.Sys().(syscall.WaitStatus) //nolint:errcheck,forcetypeassert
	}

	if status.Exited() {
		if status.ExitStatus() == serviceExitDisable {
			logInfof("%s/%s: PID %d finished and disabled itself", name, stage, pid)
		} else {
			if status.ExitStatus() != 0 {
				maybeSetExitCode(exitServiceFailure, nil)
			}
			logInfof("%s/%s: PID %d finished with status %d", name, stage, pid, status.ExitStatus())
		}
	} else {
		// If process finished because of the signal but we have not been terminating it, we see it is as a process error.
		if ctx.Err() == nil {
			maybeSetExitCode(exitServiceFailure, nil)
		}
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, pid, status.Signal())
	}

	return nil
}

func terminateService(runCmd *exec.Cmd, name string, jsonName []byte, p string) errors.E {
	logInfof("%s/run: terminating", name)
	r := path.Join(p, "terminate")
	cmd := exec.Command(r)
	cmd.Dir = p
	cmd.Env = append(os.Environ(), fmt.Sprintf("DINIT_PID=%d", runCmd.Process.Pid))

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, e := os.Pipe()
	if e != nil {
		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, e := os.Pipe()
	if e != nil {
		// This will not be used.
		stdout.Close()
		stdoutWriter.Close()

		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stderr = stderrWriter

	err := cmdRun(cmd)
	if err == nil {
		defer removeRunningChildPid(cmd.Process.Pid)
	}

	// The child process has inherited the pipe file, so close the copy held in this process.
	stdoutWriter.Close()
	stdoutWriter = nil //nolint:wastedassign
	stderrWriter.Close()
	stderrWriter = nil //nolint:wastedassign

	if err != nil {
		// These will not be used.
		stdout.Close()
		stderr.Close()

		// If terminate program does not exist, we send SIGTERM instead.
		if errors.Is(err, os.ErrNotExist) {
			logInfof("%s/run: sending SIGTERM to PID %d", name, runCmd.Process.Pid)

			e := runCmd.Process.Signal(unix.SIGTERM)
			if e != nil {
				if processNotExist(e) {
					return nil
				}
				err = errors.WithStack(e)
				maybeSetExitCode(exitDinitFailure, err)
				return err
			}

			return nil
		}

		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	logInfof("%s/term: running with PID %d", name, cmd.Process.Pid)

	var status syscall.WaitStatus
	return doRedirectAndWait(context.Background(), cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
		err := errors.WithStack(cmd.Wait())
		return cmd.ProcessState, err
	}, &status, "term", name, jsonName, stdout, stderr)
}

func runService(ctx context.Context, g *errgroup.Group, name, p string) errors.E {
	logInfof("%s/run: starting", name)
	jsonName, e := json.Marshal(name)
	if e != nil {
		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	r := path.Join(p, "run")
	// We do not use CommandContext here because we want to run finishService
	// inside the errgroup and count it with knownRunningChildren.
	cmd := exec.Command(r)
	cmd.Dir = p

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, e := os.Pipe()
	if e != nil {
		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, e := os.Pipe()
	if e != nil {
		// This will not be used.
		stdout.Close()
		stdoutWriter.Close()

		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stderr = stderrWriter

	err := cmdRun(cmd)
	if err == nil {
		defer removeRunningChildPid(cmd.Process.Pid)
	}

	// The child process has inherited the pipe file, so close the copy held in this process.
	stdoutWriter.Close()
	stdoutWriter = nil //nolint:wastedassign
	stderrWriter.Close()
	stderrWriter = nil //nolint:wastedassign

	if err != nil {
		// These will not be used.
		stdout.Close()
		stderr.Close()

		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	// When the service finishes (which is when this function returns)
	// we finish all other services as well and exit the program.
	var status syscall.WaitStatus
	defer func() {
		// If exit status is anything other than serviceExitDisable (including just initialized WaitStatus), we call cancel.
		if status.ExitStatus() != serviceExitDisable {
			MainCancel()
		}
	}()

	logInfof("%s/run: running with PID %d", name, cmd.Process.Pid)

	done := make(chan struct{})
	defer close(done)

	// We terminate the process if context is canceled.
	knownRunningChildren.Add(1)
	g.Go(func() error {
		defer knownRunningChildren.Add(-1)

		select {
		case <-ctx.Done():
			return terminateService(cmd, name, jsonName, p) //nolint:contextcheck
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	// We pass stdout through the log program of the service, if one exists.
	stdout, err = logService(ctx, g, name, jsonName, p, stdout, done)
	if err != nil {
		if debugLog {
			logErrorf("%s/log: error running: % -+#.1v", name, err)
		} else {
			logErrorf("%s/log: error running: %s", name, err)
		}
		// We already logged the error, so we pass nil here.
		maybeSetExitCode(exitDinitFailure, nil)
		// Let's terminate everything. We do not return here but continue to wait for the service
		// itself to finish, which should finish after we called MainCancel anyway.
		MainCancel()
	}

	err2 := doRedirectAndWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
		return cmd.ProcessState, errors.WithStack(cmd.Wait())
	}, &status, "run", name, jsonName, stdout, stderr)

	return errors.Join(err, err2)
}

// logService runs the log program if it exists and passes service's stdout to its stdin.
// If starting the log program fails for any reason (except if the program does not exist),
// logService returns nil for new stdout.
func logService(ctx context.Context, g *errgroup.Group, name string, jsonName []byte, p string, serviceStdout *os.File, done <-chan struct{}) (*os.File, errors.E) {
	r := path.Join(p, "log", "run")

	_, e := os.Stat(r)
	// If log program does not exist, we just return.
	if errors.Is(e, os.ErrNotExist) {
		return serviceStdout, nil
	}

	logInfof("%s/log: starting", name)

	cmd := exec.Command(r)
	cmd.Stdin = serviceStdout
	cmd.Dir = path.Join(p, "log")

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, e := os.Pipe()
	if e != nil {
		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return nil, err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, e := os.Pipe()
	if e != nil {
		// This will not be used.
		stdout.Close()
		stdoutWriter.Close()

		err := errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return nil, err
	}
	cmd.Stderr = stderrWriter

	err := cmdRun(cmd)

	// The child process has inherited the pipe file, so close the copy held in this process.
	stdoutWriter.Close()
	stdoutWriter = nil //nolint:wastedassign
	stderrWriter.Close()
	stderrWriter = nil //nolint:wastedassign

	if err != nil {
		// These will not be used.
		stdout.Close()
		stderr.Close()

		// Even if log program does not exist at this point, we
		// still return the error because it existed above.

		maybeSetExitCode(exitDinitFailure, err)
		return nil, err
	}

	logInfof("%s/log: running with PID %d", name, cmd.Process.Pid)

	// We do not cancel the process if context is canceled. We instead leave to
	// the process to exit by itself when its stdin (service's stdout) gets closed.
	knownRunningChildren.Add(1)
	g.Go(func() error {
		defer knownRunningChildren.Add(-1)

		defer removeRunningChildPid(cmd.Process.Pid)

		// When the log process finishes (which is when this goroutine returns)
		// we finish all other services as well and exit the program unless the
		// main process has finished first. Then we leave to the main process
		// to decide on that. This allows the main process to disable itself.
		defer func() {
			// We give a bit of time to the main process to finish first.
			timer := time.NewTimer(waitForDone)
			defer timer.Stop()

			select {
			case <-done:
				// The main process finished first.
				return
			case <-ctx.Done():
				// Something else cancelled the context,
				// we do not have to do it.
				return
			case <-timer.C:
				// Waiting for the main process to finish first expired.
				// We cancel the context.
				MainCancel()
			}
		}()

		// We do not pass stdout here but return it so that it is redirected with the run stage.
		var status syscall.WaitStatus
		return doRedirectAndWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
			err := errors.WithStack(cmd.Wait())
			return cmd.ProcessState, err
		}, &status, "log", name, jsonName, nil, stderr)
	})

	// We return stdout here so that it is redirected with the run stage.
	return stdout, nil
}

var (
	processedPids   = map[int]bool{} //nolint:gochecknoglobals
	processedPidsMu sync.Mutex       //nolint:gochecknoglobals
)

// ProcessPid could be called multiple times on the same PID (of the same process) so
// it has to make sure it behaves well if that happens.
func ProcessPid(ctx context.Context, g *errgroup.Group, policy policyFunc, pid int, waiting chan<- struct{}) {
	processedPidsMu.Lock()
	defer processedPidsMu.Unlock()
	if processedPids[pid] {
		return
	}
	// We check once more if this is our own child. We check this again because
	// it could happen that a child was made between us calling in reparenting
	// function first hasRunningChildPid and then processPid.
	if hasRunningChildPid(pid) {
		return
	}
	processedPids[pid] = true
	knownRunningChildren.Add(1)
	g.Go(func() error {
		defer knownRunningChildren.Add(-1)

		// We call removeProcessedPid to not have processedPids grow and grow.
		// We can do this at this point and it will not make processPid misbehave if it is called
		// multiple times on the same PID (of the same process), because policy functions return
		// when the associated process has finished and can be called without an issue with PID
		// of a non-existing process (before PID gets recycled though).
		defer removeProcessedPid(pid)

		// We want to make sure we process only mature processes. Otherwise it might happen that we process
		// a process which has double forked (to daemonize) and got reparented to dinit, but has not yet
		// called exec. Then inspecting its command line shows information from parent process.
		age, err := ProcessAge(pid)
		if err != nil {
			if processNotExist(err) {
				// Not a problem, the process does not exist anymore, we do not have to do anything about it anymore.
				// In this case it is OK if the policy gets called multiple times, it will just not do anything anymore.
				return nil
			}
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
		a := matureProcessAge - age
		if a > 0 {
			time.Sleep(a)
		}

		return policy(ctx, g, pid, waiting)
	})
}

func removeProcessedPid(pid int) {
	processedPidsMu.Lock()
	defer processedPidsMu.Unlock()
	if !processedPids[pid] {
		panic(errors.New("removing processed PID which does not exist"))
	}
	delete(processedPids, pid)
}

// When the context is canceled we still continue processing reparented processes,
// but we force the policy to be reparentingTerminate to terminate reparented processes
// as soon as possible. The function itself returns only after the context has been
// canceled and there is no known running children anymore.
func reparenting(ctx context.Context, g *errgroup.Group, policy policyFunc) errors.E {
	// Processes get reparented to the main thread which has task ID matching PID.
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", mainPid, mainPid)
	ctxDone := ctx.Done()
	// It is OK if some SIGCHLD signal is missed because we are checking for reparented
	// processes (and thus zombies as well) at a regular interval anyway.
	sigchild := make(chan os.Signal, 1)
	signal.Notify(sigchild, unix.SIGCHLD)
	defer signal.Stop(sigchild)
	ticker := time.NewTicker(reparentingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			// If the context is canceled, we just terminate any reparented process.
			policy = ReparentingTerminate
			// Disable this select case.
			ctxDone = nil
			// Increase the rate at which we are checking for new reparented processes.
			ticker.Reset(reparentingTerminatingInterval)
			continue
		case <-sigchild:
		case <-ticker.C:
		}

		childrenData, e := os.ReadFile(childrenPath)
		if e != nil {
			if processNotExist(e) {
				continue
			}
			errE := errors.WithMessage(e, "unable to read process children from")
			errors.Details(errE)["path"] = childrenPath
			maybeSetExitCode(exitDinitFailure, errE)
			return errE
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, e := strconv.Atoi(childPid)
			if e != nil {
				errE := errors.WithMessage(e, "failed to parse PID")
				errors.Details(errE)["pid"] = childPid
				maybeSetExitCode(exitDinitFailure, errE)
				return errE
			}
			if !hasRunningChildPid(p) {
				// If this is not our own child we call configured policy.
				// We do not care when pid processing is waiting.
				ProcessPid(ctx, g, policy, p, nil)
			}
		}

		// The context is canceled, there is no more direct children and no more known running children. Return.
		// It is important that we return only after the context is canceled so that we give time for runServices
		// to do its job and not return before services even start.
		k := knownRunningChildren.Load()
		if k < 0 {
			panic(errors.New("negative known running children count"))
		}
		if ctx.Err() != nil && len(childrenPids) == 0 && k == 0 {
			return errors.WithStack(ctx.Err())
		}
	}
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessCommandLine(pid int) (string, errors.E) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, e := os.ReadFile(cmdlinePath)
	if e != nil {
		if processNotExist(e) {
			return "", errors.WithStack(os.ErrProcessDone)
		}
		return "", errors.WithStack(e)
	}
	return string(bytes.TrimRight(bytes.ReplaceAll(cmdlineData, []byte("\x00"), []byte(" ")), " ")), nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessStatus(pid int) (string, []string, errors.E) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, e := os.ReadFile(statPath)
	if e != nil {
		if processNotExist(e) {
			return "", nil, errors.WithStack(os.ErrProcessDone)
		}
		return "", nil, errors.WithStack(e)
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 3 { //nolint:gomnd
		errE := errors.New("could not match process status")
		errors.Details(errE)["path"] = statPath
		errors.Details(errE)["data"] = statData
		return "", nil, errE
	}
	return string(match[1]), strings.Fields(string(match[2])), nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
// TODO: Should we use waitid with WEXITED|WNOHANG|WNOWAIT options?
func IsZombie(pid int) (bool, errors.E) {
	_, info, err := getProcessStatus(pid)
	if err != nil {
		return false, err
	}
	return info[procStatState-procStatOffset] == "Z", nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func ProcessAge(pid int) (time.Duration, errors.E) {
	_, info, err := getProcessStatus(pid)
	if err != nil {
		return 0, err
	}
	startTimeString := info[procStatStartTime-procStatOffset]
	startTime, e := strconv.ParseUint(startTimeString, 10, 64)
	if e != nil {
		errE := errors.WithMessage(e, "failed to parse process start time")
		errors.Details(errE)["value"] = startTimeString
		return 0, errE
	}
	// We first compute time.Second / _SC_CLK_TCK to not lose precision.
	startTimeSinceBoot := time.Duration(startTime * (uint64(time.Second) / uint64(_SC_CLK_TCK)))

	uptimeData, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return 0, errors.WithStack(e)
	}
	uptimeString := strings.Fields(string(uptimeData))[0]
	uptime, e := strconv.ParseFloat(uptimeString, 64)
	if e != nil {
		errE := errors.WithMessage(e, "failed to parse uptime")
		errors.Details(errE)["value"] = uptimeString
		return 0, errE
	}

	return time.Duration(uptime*float64(time.Second)) - startTimeSinceBoot, nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessProgramName(pid int) (string, errors.E) {
	name, _, err := getProcessStatus(pid)
	if err != nil {
		return "", err
	}
	return name, nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func GetProcessInfo(pid int) (string, string, string, errors.E) {
	cmdline, err := getProcessCommandLine(pid)
	if err != nil {
		return "", "", "", err
	}
	name := ""
	// Take the first (space delimited) part of the cmdline.
	if fields := strings.Fields(cmdline); len(fields) > 0 {
		name = fields[0]
		// If name contains /, take the last part.
		splitName := strings.Split(name, "/")
		if len(splitName) > 1 {
			name = splitName[len(splitName)-1]
		}
	}
	if name == "" {
		// getProcessCommandLine returns an empty string on a zombie process, so we use getProcessProgramName then.
		name, err = getProcessProgramName(pid)
		if err != nil {
			return "", "", "", err
		}
	}
	if name == "" {
		name = "unknown"
	}
	// We misuse pid as stage to differentiate between multiple reparented processes with same command line.
	stage := strconv.Itoa(pid)
	return cmdline, name, stage, nil
}

func checkProcess(p *os.Process, name, stage, cmdline string) (bool, errors.E) {
	zombie, err := IsZombie(p.Pid)
	if err != nil {
		if processNotExist(err) {
			// The process does not exist anymore, nothing for us to do anymore.
			return false, nil
		}
		maybeSetExitCode(exitDinitFailure, err)
		return false, err
	}
	if zombie {
		return false, reapZombie(p, name, stage, cmdline)
	}
	return true, nil
}

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue adopting reparented processes (and terminating them as soon as possible).
func ReparentingAdopt(ctx context.Context, g *errgroup.Group, pid int, waiting chan<- struct{}) errors.E {
	cmdline, name, stage, err := GetProcessInfo(pid)
	if err != nil {
		if processNotExist(err) {
			// Not a problem, the process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if the policy gets called multiple times, it will just not do anything anymore.
			return nil
		}
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	jsonName, e := json.Marshal(name)
	if e != nil {
		err = errors.WithStack(e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	// When adopting, then when the process finishes (which is when this function returns)
	// we finish all other services as well and exit the program.
	defer MainCancel()

	p, _ := os.FindProcess(pid) // This call cannot fail.

	// Checking if the process is a zombie is primarily cosmetic to reduce
	// potentially misleading logging messages.
	ok, err := checkProcess(p, name, stage, cmdline)
	if !ok || err != nil {
		return err
	}

	if cmdline != "" {
		logWarnf("%s/%s: adopting reparented child process with PID %d: %s", name, stage, pid, cmdline)
	} else {
		logWarnf("%s/%s: adopting reparented child process with PID %d", name, stage, pid)
	}

	// knownRunningChildren is managed by the processPid function for all policies, runningChildren on
	// the other hand is managed by policies themselves because not all policies set them (e.g., terminate
	// does not, adopt does). It is not critical when setRunningChildPid is called because the whole
	// processPid is protected by the processedPids map and while this policy function is running
	// the process' pid cannot be processed again in reparenting.
	setRunningChildPid(pid, true)
	defer removeRunningChildPid(pid)

	stdout, stderr, err := pcontrol.RedirectAllStdoutStderr(debugLog, logWarnf, pid)
	if err != nil {
		if debugLog {
			logWarnf("%s/%s: error redirecting stdout and stderr: % -+#.1v", name, stage, err)
		} else {
			logWarnf("%s/%s: error redirecting stdout and stderr: %s", name, stage, err)
		}

		// We check the process again on error. It might happen that the process does not
		// exist anymore and because pcontrol uses wait it might have reaped the process.
		// Checking here prevents errors later on.
		ok, err := checkProcess(p, name, stage, cmdline)
		if err != nil {
			return errors.WithMessagef(err, "%s/%s", name, stage)
		}
		if !ok {
			logInfof("%s/%s: PID %d finished before adopting complete", name, stage, p.Pid)
			return nil
		}
	}

	done := make(chan struct{})
	defer close(done)

	// We terminate the process if context is canceled.
	g.Go(func() error {
		select {
		case <-ctx.Done():
			logInfof("%s/%s: terminating", name, stage)
			logInfof("%s/%s: sending SIGTERM to PID %d", name, stage, pid)

			e := p.Signal(unix.SIGTERM)
			if e != nil {
				if processNotExist(e) {
					return nil
				}
				err := errors.WithStack(e)
				maybeSetExitCode(exitDinitFailure, err)
				return err
			}

			return ctx.Err() //nolint:wrapcheck
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	if waiting != nil {
		close(waiting)
	}

	var status syscall.WaitStatus
	return doRedirectAndWait(ctx, pid, func() (*os.ProcessState, errors.E) {
		state, e := p.Wait()
		return state, errors.WithStack(e)
	}, &status, stage, name, jsonName, stdout, stderr)
}

func reapZombie(p *os.Process, name, stage, cmdline string) errors.E {
	if cmdline != "" {
		logWarnf("%s/%s: reaping process with PID %d: %s", name, stage, p.Pid, cmdline)
	} else {
		logWarnf("%s/%s: reaping process with PID %d", name, stage, p.Pid)
	}

	return doWait(p, name, stage)
}

func doWait(p *os.Process, name, stage string) errors.E {
	state, e := p.Wait()
	if e != nil {
		err := errors.WithMessagef(e, "%s/%s: error waiting for the process", name, stage)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	status := state.Sys().(syscall.WaitStatus) //nolint:errcheck,forcetypeassert

	if status.Exited() {
		logInfof("%s/%s: PID %d finished with status %d", name, stage, p.Pid, status.ExitStatus())
	} else {
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, p.Pid, status.Signal())
	}

	return nil
}

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue terminating reparented processes.
func ReparentingTerminate(_ context.Context, g *errgroup.Group, pid int, waiting chan<- struct{}) errors.E {
	cmdline, name, stage, err := GetProcessInfo(pid)
	if err != nil {
		if processNotExist(err) {
			// Not a problem, the process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if the policy gets called multiple times, it will just not do anything anymore.
			return nil
		}
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	p, _ := os.FindProcess(pid) // This call cannot fail.

	// Checking if the process is a zombie is primarily cosmetic to reduce
	// potentially misleading logging messages.
	zombie, err := IsZombie(pid)
	if err != nil {
		if processNotExist(err) {
			// The process does not exist anymore, nothing for us to do anymore.
			return nil
		}
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	if zombie {
		return reapZombie(p, name, stage, cmdline)
	}

	if cmdline != "" {
		logWarnf("%s/%s: terminating reparented child process with PID %d: %s", name, stage, pid, cmdline)
	} else {
		logWarnf("%s/%s: terminating reparented child process with PID %d", name, stage, pid)
	}

	done := make(chan struct{})
	defer close(done)

	g.Go(func() error {
		logInfof("%s/%s: sending SIGTERM to PID %d", name, stage, pid)

		e := p.Signal(unix.SIGTERM)
		if e != nil {
			if processNotExist(e) {
				return nil
			}
			err := errors.WithStack(e)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}

		// We wait between SIGTERM and SIGKILL.
		timer := time.NewTimer(reparentingKillTimeout)
		defer timer.Stop()

		// We do not care about context cancellation. Even if the context is canceled we still
		// want to give full reparentingKillTimeout to the process before killing it. If that
		// is longer than what Docker container has as a whole, everything will be killed anyway.
		select {
		case <-timer.C:
			// We waited enough after SIGTERM, we continue after the select.
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}

		logInfof("%s/%s: sending SIGKILL to PID %d", name, stage, pid)

		e = p.Signal(unix.SIGKILL)
		if e != nil {
			if processNotExist(e) {
				return nil
			}
			err := errors.WithStack(e)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}

		return nil
	})

	if waiting != nil {
		close(waiting)
	}

	// By waiting we are also making sure that dinit does not exit before
	// this reparented child process exits.
	return doWait(p, name, stage)
}
