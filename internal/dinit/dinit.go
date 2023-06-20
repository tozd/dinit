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

const etcService = "/etc/service"

// We check for new reparented processes at a regular interval and trigger configured
// reparenting policy on them. Reparenting also happens on SIGCHLD signal so interval
// between reparenting checks can be shorter.
const reparentingInterval = time.Second

// When dinit is stopping (the context is canceled) we increase the rate at which we
// check for new reparented processes. By default docker stop waits for 10 seconds
// before it kills processes if container does not exit, so we want to detect any
// reparenting which might happen during shutdown and have time to send those processes
// SIGTERM as well. This can happen multiple times if terminating the first wave of
// reparented processes trigger another wave. So keep this under one second or so.
// This is also approximately the time reparenting function waits before returning
// after there is no more known running children.
const reparentingStoppingInterval = reparentingInterval / 10

// How long to wait after SIGTERM to send SIGKILL to a reparented process?
var reparentingKillTimeout = 30 * time.Second

const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

const (
	exitSuccess      = 0
	exitDinitFailure = 1
	// 2 is used when Golang runtime fails due to an unrecovered panic or an unexpected runtime condition.
	exitServiceFailure = 3
)

var procStatRegexp = regexp.MustCompile(`\((.*)\) (.)`)

// We manually prefix logging.
const logFlags = 0

type policyFunc = func(ctx context.Context, g *errgroup.Group, pid int) errors.E

var debugLog = false

func timestamp() string {
	return time.Now().UTC().Format(RFC3339Milli)
}

var logDebug = func(msg any) { //nolint:unused
	log.Printf(timestamp()+" dinit: debug: %s", msg)
}

var logDebugf = func(msg string, args ...any) {
	log.Printf(timestamp()+" dinit: debug: "+msg, args...)
}

var logInfo = func(msg any) { //nolint:unused
	log.Printf(timestamp()+" dinit: info: %s", msg)
}

var logInfof = func(msg string, args ...any) {
	log.Printf(timestamp()+" dinit: info: "+msg, args...)
}

var logWarn = func(msg any) {
	log.Printf(timestamp()+" dinit: warning: %s", msg)
}

var logWarnf = func(msg string, args ...any) {
	log.Printf(timestamp()+" dinit: warning: "+msg, args...)
}

var logError = func(msg any) { //nolint:unused
	log.Printf(timestamp()+" dinit: error: %s", msg)
}

var logErrorf = func(msg string, args ...any) {
	log.Printf(timestamp()+" dinit: error: "+msg, args...)
}

func processNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) || errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone)
}

var mainContext, mainCancel = context.WithCancel(context.Background())

var mainPid = os.Getpid()

var (
	exitCode   *int
	exitCodeMu sync.Mutex
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
		buf := &strings.Builder{}
		_, _ = errors.StackFormat(buf, "%+v", callers())
		if err != nil {
			logDebugf("setting exit code to %d at (most recent call first):\n%s\ncaused by the error:\n\n%+v", code, buf.String(), err)
		} else {
			logDebugf("setting exit code to %d at (most recent call first):\n%s", code, buf.String())
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

var stdOutLog = log.New(os.Stdout, "", logFlags)

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

	go handleStopSignals()

	g, ctx := errgroup.WithContext(mainContext)

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
		return runServices(ctx, g)
	})

	// The assertion here is that once runServices and reparenting goroutines return
	// (and any they additionally created while running), no more goroutines will be
	// added to the g errgroup.
	err := errors.WithStack(g.Wait())
	if err != nil && !errors.Is(err, context.Canceled) {
		maybeSetExitCode(exitDinitFailure, nil)
		if debugLog {
			logErrorf("exiting: %+v", err)
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

func handleStopSignals() {
	// We do not handle SIGQUIT because that is handled specially by Go runtime.
	c := make(chan os.Signal, 2) //nolint:gomnd
	signal.Notify(c, unix.SIGTERM, unix.SIGINT)
	for s := range c {
		if mainContext.Err() != nil {
			logInfof("got signal %d, already stopping children", s)
		} else {
			logInfof("got signal %d, stopping children", s)
			// Even if children complain being terminated, we still exit with 0.
			maybeSetExitCode(exitSuccess, nil)
			mainCancel()
		}
	}
}

// A counter of all known running sub-processes. We have to make sure we do not call
// errgroup's Add after its Wait has already stopped waiting. We do this by making sure
// reparenting function only returns once the context is canceled and there are no more
// known running children.
var knownRunningChildren = atomic.Int32{}

// A map of running sub-processes we started or adopted.
var (
	runningChildren   = map[int]bool{}
	runningChildrenMu sync.RWMutex
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

func runServices(ctx context.Context, g *errgroup.Group) errors.E {
	entries, e := os.ReadDir(etcService)
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
		p := path.Join(etcService, name)
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
		mainCancel()
	}
	return nil
}

func redirectToLogWithPrefix(l *log.Logger, stage, name, input string, reader io.ReadCloser) {
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
		logWarnf("%s/%s: error reading %s: %s", name, stage, input, e)
	}
}

func redirectStderrWithPrefix(stage, name string, reader io.ReadCloser) {
	redirectToLogWithPrefix(log.Default(), stage, name, "stderr", reader)
}

func redirectStdoutWithPrefix(stage, name string, reader io.ReadCloser) {
	redirectToLogWithPrefix(stdOutLog, stage, name, "stdout", reader)
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
					logWarnf("%s/%s: error writing stdout: %s", name, stage, e)
				}
			} else {
				logWarnf("%s/%s: not JSON stdout: %s\n", name, stage, line)
			}
		}
	}

	e := scanner.Err()
	// Reader can get closed and we ignore that.
	if e != nil && !errors.Is(e, os.ErrClosed) {
		logWarnf("%s/%s: error reading stdout: %s", name, stage, e)
	}
}

func doRedirectAndWait(ctx context.Context, pid int, wait func() (*os.ProcessState, errors.E), stage, name string, jsonName []byte, stdout, stderr *os.File) errors.E {
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

	var status syscall.WaitStatus
	state, err := wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// If we are here, process finished successfully but the context has been canceled so err was set, so we just ignore the err.
			status = state.Sys().(syscall.WaitStatus) //nolint:errcheck
		} else if state != nil && !state.Success() {
			// This is a condition in Wait when err is set when process fails, so we just ignore the err.
			status = state.Sys().(syscall.WaitStatus) //nolint:errcheck
		} else {
			err = errors.Errorf("%s/%s: error waiting for the process: %w", name, stage, err)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
	} else {
		status = state.Sys().(syscall.WaitStatus) //nolint:errcheck
	}

	if status.Exited() {
		if status.ExitStatus() != 0 {
			maybeSetExitCode(exitServiceFailure, nil)
		}
		logInfof("%s/%s: PID %d finished with status %d", name, stage, pid, status.ExitStatus())
	} else {
		// If process finished because of the signal but we have not been stopping it, we see it is as a process error.
		if ctx.Err() == nil {
			maybeSetExitCode(exitServiceFailure, nil)
		}
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, pid, status.Signal())
	}

	return nil
}

func finishService(runCmd *exec.Cmd, name string, jsonName []byte, p string) errors.E {
	logInfof("%s/run: finishing", name)
	r := path.Join(p, "finish")
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

		// If finish program does not exist, we send SIGTERM instead.
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

	logInfof("%s/finish: running with PID %d", name, cmd.Process.Pid)

	return doRedirectAndWait(context.Background(), cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
		err := errors.WithStack(cmd.Wait())
		return cmd.ProcessState, err
	}, "finish", name, jsonName, stdout, stderr)
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
	defer mainCancel()

	logInfof("%s/run: running with PID %d", name, cmd.Process.Pid)

	done := make(chan struct{})
	defer close(done)

	// We cancel the process if context is canceled.
	knownRunningChildren.Add(1)
	g.Go(func() error {
		defer knownRunningChildren.Add(-1)

		select {
		case <-ctx.Done():
			return finishService(cmd, name, jsonName, p) //nolint:contextcheck
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	// We pass stdout through the log program of the service, if one exists.
	stdout, err = logService(ctx, g, name, jsonName, p, stdout)
	if err != nil {
		if debugLog {
			logErrorf("%s/log: error running: %+v", name, err)
		} else {
			logErrorf("%s/log: error running: %s", name, err)
		}
		// We already logged the error, so we pass nil here.
		maybeSetExitCode(exitDinitFailure, nil)
		// Let's stop everything. We do not return here but continue to wait for the service
		// itself to finish, which should finish after we called mainCancel anyway.
		mainCancel()
	}

	err2 := doRedirectAndWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
		return cmd.ProcessState, errors.WithStack(cmd.Wait())
	}, "run", name, jsonName, stdout, stderr)

	return errors.Join(err, err2)
}

// logService runs the log program if it exists and passes service's stdout to its stdin.
// If starting the log program fails for any reason (except if the program does not exist),
// logService returns nil for new stdout.
func logService(ctx context.Context, g *errgroup.Group, name string, jsonName []byte, p string, serviceStdout *os.File) (*os.File, errors.E) {
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
		// we finish all other services as well and exit the program.
		defer mainCancel()

		// We do not pass stdout here but return it so that it is redirected with the run stage.
		return doRedirectAndWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, errors.E) {
			err := errors.WithStack(cmd.Wait())
			return cmd.ProcessState, err
		}, "log", name, jsonName, nil, stderr)
	})

	// We return stdout here so that it is redirected with the run stage.
	return stdout, nil
}

var (
	processedPids   = map[int]bool{}
	processedPidsMu sync.Mutex
)

// ProcessPid could be called multiple times on the same PID (of the same process) so
// it has to make sure it behaves well if that happens.
func ProcessPid(ctx context.Context, g *errgroup.Group, policy policyFunc, pid int) {
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
		return policy(ctx, g, pid)
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
			ticker.Reset(reparentingStoppingInterval)
			continue
		case <-sigchild:
		case <-ticker.C:
		}

		childrenData, e := os.ReadFile(childrenPath)
		if e != nil {
			if processNotExist(e) {
				continue
			}
			err := errors.Errorf("unable to read process children from %s: %w", childrenPath, e)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, e := strconv.Atoi(childPid)
			if e != nil {
				err := errors.Errorf("failed to parse PID %s: %w", childPid, e)
				maybeSetExitCode(exitDinitFailure, err)
				return err
			}
			if !hasRunningChildPid(p) {
				// If this is not our own child we call configured policy.
				ProcessPid(ctx, g, policy, p)
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
// TODO: Should we use waitid with WEXITED|WNOHANG|WNOWAIT options?
func IsZombie(pid int) (bool, errors.E) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, e := os.ReadFile(statPath)
	if e != nil {
		if processNotExist(e) {
			return false, errors.WithStack(os.ErrProcessDone)
		}
		return false, errors.WithStack(e)
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 3 { //nolint:gomnd
		return false, errors.Errorf("could not match process state in %s: %s", statPath, statData)
	}
	return string(match[2]) == "Z", nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessProgramName(pid int) (string, errors.E) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, e := os.ReadFile(statPath)
	if e != nil {
		if processNotExist(e) {
			return "", errors.WithStack(os.ErrProcessDone)
		}
		return "", errors.WithStack(e)
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 3 { //nolint:gomnd
		return "", errors.Errorf("could not match executable name in %s: %s", statPath, statData)
	}
	return string(match[1]), nil
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

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue adopting reparented processes (and terminating them as soon as possible).
func ReparentingAdopt(ctx context.Context, g *errgroup.Group, pid int) errors.E {
	cmdline, name, stage, err := GetProcessInfo(pid)
	if err != nil {
		if processNotExist(err) {
			// Not a problem, the process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if reparentingAdopt gets called multiple times,
			// it will just not do anything anymore.
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

	// When adopting, then when the process stops (which is when this function returns)
	// we stop all other services and exit the program.
	defer mainCancel()

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
			logWarnf("%s/%s: error redirecting stdout and stderr: %+v", name, stage, err)
		} else {
			logWarnf("%s/%s: error redirecting stdout and stderr: %s", name, stage, err)
		}
	}

	done := make(chan struct{})
	defer close(done)

	// We cancel the process if context is canceled.
	g.Go(func() error {
		select {
		case <-ctx.Done():
			logInfof("%s/%s: finishing", name, stage)
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

			return ctx.Err()
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	return doRedirectAndWait(ctx, pid, func() (*os.ProcessState, errors.E) {
		state, e := p.Wait()
		return state, errors.WithStack(e)
	}, stage, name, jsonName, stdout, stderr)
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
		err := errors.Errorf("%s/%s: error waiting for the process: %w", name, stage, e)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	status := state.Sys().(syscall.WaitStatus) //nolint:errcheck

	if status.Exited() {
		logInfof("%s/%s: PID %d finished with status %d", name, stage, p.Pid, status.ExitStatus())
	} else {
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, p.Pid, status.Signal())
	}

	return nil
}

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue terminating reparented processes.
func ReparentingTerminate(_ context.Context, g *errgroup.Group, pid int) errors.E {
	cmdline, name, stage, err := GetProcessInfo(pid)
	if err != nil {
		if processNotExist(err) {
			// Not a problem, the process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if reparentingTerminate gets called multiple times,
			// it will just not do anything anymore.
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

	// By waiting we are also making sure that dinit does not exit before
	// this reparented child process exits.
	return doWait(p, name, stage)
}
