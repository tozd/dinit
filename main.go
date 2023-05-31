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

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
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
const reparentingKillTimeout = 30 * time.Second

const (
	exitSuccess      = 0
	exitDinitFailure = 1
	// 2 is used when Golang runtime fails due to an unrecovered panic or an unexpected runtime condition.
	exitServiceFailure = 3
)

var procStatRegexp = regexp.MustCompile(`\((.*)\) (.)`)

// TODO: Output milliseconds. See: https://github.com/golang/go/issues/60249
const logFlags = log.Ldate | log.Ltime | log.LUTC

type policyFunc = func(ctx context.Context, g *errgroup.Group, pid int) error

var debugLog = false

var logDebug = func(msg any) {
	log.Printf("dinit: debug: %s", msg)
}

var logDebugf = func(msg string, args ...any) {
	log.Printf("dinit: debug: "+msg, args...)
}

var logInfo = func(msg any) {
	log.Printf("dinit: info: %s", msg)
}

var logInfof = func(msg string, args ...any) {
	log.Printf("dinit: info: "+msg, args...)
}

var logWarn = func(msg any) {
	log.Printf("dinit: warning: %s", msg)
}

var logWarnf = func(msg string, args ...any) {
	log.Printf("dinit: warning: "+msg, args...)
}

var logError = func(msg any) {
	log.Printf("dinit: error: %s", msg)
}

var logErrorf = func(msg string, args ...any) {
	log.Printf("dinit: error: "+msg, args...)
}

func processNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) || errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone)
}

var mainContext, mainCancel = context.WithCancel(context.Background())

var mainPid = os.Getpid()

var exitCode *int = nil
var exitCodeMu sync.Mutex

func maybeSetExitCode(code int, err error) {
	exitCodeMu.Lock()
	defer exitCodeMu.Unlock()
	if exitCode == nil {
		exitCode = &code
	}
	if debugLog && code == exitDinitFailure {
		if err != nil {
			logDebugf("setting exit code to %d at:\n%s\ncaused by the error: %+v", code, debug.Stack(), err)
		} else {
			logDebugf("setting exit code to %d at:\n%s", code, debug.Stack())
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

func main() {
	log.SetFlags(logFlags)

	switch level := os.Getenv("DINIT_LOG_LEVEL"); level {
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
			return reparenting(ctx, g, reparentingAdopt)
		})
	case "terminate", "": // Default reparenting policy.
		g.Go(func() error {
			return reparenting(ctx, g, reparentingTerminate)
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
	err := g.Wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Nothing.
		} else {
			maybeSetExitCode(exitDinitFailure, nil)
			if debugLog {
				logErrorf("exiting: %+v", err)
			} else {
				logErrorf("exiting: %s", err)
			}
		}
	}

	status := getExitCode()
	logInfof("dinit exiting with status %d", status)
	os.Exit(status)
}

func handleStopSignals() {
	// We do not handle SIGQUIT because that is handled specially by Go runtime.
	c := make(chan os.Signal, 2)
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
var runningChildren = map[int]bool{}
var runningChildrenMu sync.RWMutex

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
func cmdRun(cmd *exec.Cmd) error {
	runningChildrenMu.Lock()
	defer runningChildrenMu.Unlock()

	err := cmd.Start()

	if err == nil {
		setRunningChildPid(cmd.Process.Pid, false)
	}

	return err
}

func runServices(ctx context.Context, g *errgroup.Group) error {
	entries, err := os.ReadDir(etcService)
	if err != nil {
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
		info, err := os.Stat(p)
		if err != nil {
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
			l.Printf("%s/%s: %s\n", name, stage, line)
		}
	}

	err := scanner.Err()
	// Reader can get closed and we ignore that.
	if err != nil && !errors.Is(err, os.ErrClosed) {
		logWarnf("%s/%s: error reading %s: %s", name, stage, input, err)
	}
}

func redirectStderrWithPrefix(stage, name string, reader io.ReadCloser) {
	redirectToLogWithPrefix(log.Default(), stage, name, "stderr", reader)
}

func redirectStdoutWithPrefix(stage, name string, reader io.ReadCloser) {
	redirectToLogWithPrefix(stdOutLog, stage, name, "stdout", reader)
}

func redirectJSON(stage, name string, jsonName []byte, reader io.ReadCloser) {
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	timeBuffer := make([]byte, 30)

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
				buffer.Write(now.AppendFormat(timeBuffer, "2006-01-02T15:04:05.000Z07:00"))
				buffer.WriteString(`"}`)
				buffer.WriteString("\n")
				_, err := os.Stdout.Write(buffer.Bytes())
				if err != nil {
					logWarnf("%s/%s: error writing stdout: %s", name, stage, err)
				}
			} else {
				logWarnf("%s/%s: not JSON stdout: %s\n", name, stage, line)
			}
		}
	}

	err := scanner.Err()
	// Reader can get closed and we ignore that.
	if err != nil && !errors.Is(err, os.ErrClosed) {
		logWarnf("%s/%s: error reading stdout: %s", name, stage, err)
	}
}

func doRedirectAndWait(ctx context.Context, pid int, wait func() (*os.ProcessState, error), stage, name string, jsonName []byte, stdout, stderr *os.File) error {
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
			go redirectJSON(stage, name, jsonName, stdout)
		}
	}

	var status syscall.WaitStatus
	state, err := wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// If we are here, process finished successfully but the context has been canceled so err was set, so we just ignore the err.
			status = state.Sys().(syscall.WaitStatus)
		} else if state != nil && !state.Success() {
			// This is a condition in Wait when err is set when process fails, so we just ignore the err.
			status = state.Sys().(syscall.WaitStatus)
		} else {
			err = fmt.Errorf("%s/%s: error waiting for the process: %w", name, stage, err)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
	} else {
		status = state.Sys().(syscall.WaitStatus)
	}

	if status.Exited() {
		if status.ExitStatus() != 0 {
			maybeSetExitCode(exitServiceFailure, nil)
		}
		logInfof("%s/%s: PID %d finished with status %d", name, stage, pid, status.ExitStatus())
	} else {
		// If process finished because of the signal but we have not been stopping it, we see it is as a process error.
		if ctx == nil || ctx.Err() == nil {
			maybeSetExitCode(exitServiceFailure, nil)
		}
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, pid, status.Signal())
	}

	return nil
}

func stopService(runCmd *exec.Cmd, name string, jsonName []byte, p string) error {
	logInfof("%s/run: stopping", name)
	r := path.Join(p, "stop")
	cmd := exec.Command(r)
	cmd.Dir = p

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stderr = stderrWriter

	err = cmdRun(cmd)
	if err == nil {
		defer removeRunningChildPid(cmd.Process.Pid)
	}

	// The child process has inherited the pipe file, so close the copy held in this process.
	stdoutWriter.Close()
	stdoutWriter = nil
	stderrWriter.Close()
	stderrWriter = nil

	if err != nil {
		// These will not be used.
		stdout.Close()
		stderr.Close()

		// If stop program does not exist, we send SIGTERM instead.
		if errors.Is(err, os.ErrNotExist) {
			logInfof("%s/run: sending SIGTERM to PID %d", name, runCmd.Process.Pid)

			err := runCmd.Process.Signal(unix.SIGTERM)
			if err != nil {
				if processNotExist(err) {
					return nil
				}
				maybeSetExitCode(exitDinitFailure, err)
				return err
			}

			return nil
		}
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	logInfof("%s/stop: running with PID %d", name, cmd.Process.Pid)

	return doRedirectAndWait(nil, cmd.Process.Pid, func() (*os.ProcessState, error) {
		err := cmd.Wait()
		return cmd.ProcessState, err
	}, "stop", name, jsonName, stdout, stderr)
}

func runService(ctx context.Context, g *errgroup.Group, name, p string) error {
	logInfof("%s/run: starting", name)
	jsonName, err := json.Marshal(name)
	if err != nil {
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	r := path.Join(p, "run")
	// We do not use CommandContext here because we want to run stopService
	// inside the errgroup and count it with knownRunningChildren.
	cmd := exec.Command(r)
	cmd.Dir = p

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		// This will not be used.
		stdout.Close()
		stdoutWriter.Close()

		maybeSetExitCode(exitDinitFailure, err)
		return err
	}
	cmd.Stderr = stderrWriter

	err = cmdRun(cmd)
	if err == nil {
		defer removeRunningChildPid(cmd.Process.Pid)
	}

	// The child process has inherited the pipe file, so close the copy held in this process.
	stdoutWriter.Close()
	stdoutWriter = nil
	stderrWriter.Close()
	stderrWriter = nil

	if err != nil {
		// These will not be used.
		stdout.Close()
		stderr.Close()

		// Start can fail when context is canceled, but we do not want to set
		// the exit code because of the cancellation.
		if !errors.Is(err, context.Canceled) {
			maybeSetExitCode(exitDinitFailure, err)
		}
		return err
	}

	// When the service stops (which is when this function returns)
	// we stop all other services as well and exit ourselves.
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
			return stopService(cmd, name, jsonName, p)
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	return doRedirectAndWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, error) {
		err := cmd.Wait()
		return cmd.ProcessState, err
	}, "run", name, jsonName, stdout, stderr)
}

var processedPids = map[int]bool{}
var processedPidsMu sync.Mutex

// processPid could be called multiple times on the same PID (of the same process) so
// it has to make sure it behaves well if that happens.
func processPid(ctx context.Context, g *errgroup.Group, policy policyFunc, pid int) {
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
func reparenting(ctx context.Context, g *errgroup.Group, policy policyFunc) error {
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
			policy = reparentingTerminate
			// Disable this select case.
			ctxDone = nil
			// Increase the rate at which we are checking for new reparented processes.
			ticker.Reset(reparentingStoppingInterval)
			continue
		case <-sigchild:
		case <-ticker.C:
		}

		childrenData, err := os.ReadFile(childrenPath)
		if err != nil {
			if processNotExist(err) {
				continue
			}
			err = fmt.Errorf("unable to read process children from %s: %w", childrenPath, err)
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, err := strconv.Atoi(childPid)
			if err != nil {
				err = fmt.Errorf("failed to parse PID %s: %w", childPid, err)
				maybeSetExitCode(exitDinitFailure, err)
				return err
			}
			if hasRunningChildPid(p) {
				// This is our own child.
			} else {
				// Unknown PID. We call configured policy.
				processPid(ctx, g, policy, p)
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
			return ctx.Err()
		}
	}
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessCommandLine(pid int) (string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		if processNotExist(err) {
			return "", os.ErrProcessDone
		}
		return "", err
	}
	return string(bytes.ReplaceAll(cmdlineData, []byte("\x00"), []byte(" "))), nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
// TODO: Should we use waitid with WEXITED|WNOHANG|WNOWAIT options?
func isZombie(pid int) (bool, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		if processNotExist(err) {
			return false, os.ErrProcessDone
		}
		return false, err
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 3 {
		return false, fmt.Errorf("could not match process state in %s: %s", statPath, statData)
	}
	return string(match[2]) == "Z", nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessProgramName(pid int) (string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		if processNotExist(err) {
			return "", os.ErrProcessDone
		}
		return "", err
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 3 {
		return "", fmt.Errorf("could not match executable name in %s: %s", statPath, statData)
	}
	return string(match[1]), nil
}

// This is an utility function, so we do not call maybeSetExitCode(exitDinitFailure) on
// errors but leave it to the caller to decide if and when to do so.
func getProcessInfo(pid int) (string, string, string, error) {
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
func reparentingAdopt(ctx context.Context, g *errgroup.Group, pid int) error {
	cmdline, name, stage, err := getProcessInfo(pid)
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
	jsonName, err := json.Marshal(name)
	if err != nil {
		maybeSetExitCode(exitDinitFailure, err)
		return err
	}

	// When adopting, then when the process stops (which is when this function returns)
	// we stop all other services and exit ourselves.
	defer mainCancel()

	p, _ := os.FindProcess(pid) // This call cannot fail.

	// Checking if the process is a zombie is primarily cosmetic to reduce
	// potentially misleading logging messages.
	zombie, err := isZombie(pid)
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

	stdout, stderr, err := ptraceRedirectStdoutStderr(pid)
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
			logInfof("%s/%s: stopping", name, stage)
			logInfof("%s/%s: sending SIGTERM to PID %d", name, stage, pid)

			err := p.Signal(unix.SIGTERM)
			if err != nil {
				if processNotExist(err) {
					return nil
				}
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

	return doRedirectAndWait(ctx, pid, p.Wait, stage, name, jsonName, stdout, stderr)
}

func reapZombie(p *os.Process, name, stage, cmdline string) error {
	if cmdline != "" {
		logWarnf("%s/%s: reaping process with PID %d: %s", name, stage, p.Pid, cmdline)
	} else {
		logWarnf("%s/%s: reaping process with PID %d", name, stage, p.Pid)
	}

	return doWait(p, name, stage)
}

func doWait(p *os.Process, name, stage string) error {
	var status syscall.WaitStatus
	state, err := p.Wait()
	if err != nil {
		err = fmt.Errorf("%s/%s: error waiting for the process: %w", name, stage, err)
		maybeSetExitCode(exitDinitFailure, err)
		return err
	} else {
		status = state.Sys().(syscall.WaitStatus)
	}

	if status.Exited() {
		logInfof("%s/%s: PID %d finished with status %d", name, stage, p.Pid, status.ExitStatus())
	} else {
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, p.Pid, status.Signal())
	}

	return nil
}

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue terminating reparented processes.
func reparentingTerminate(_ context.Context, g *errgroup.Group, pid int) error {
	cmdline, name, stage, err := getProcessInfo(pid)
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
	zombie, err := isZombie(pid)
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

		err := p.Signal(unix.SIGTERM)
		if err != nil {
			if processNotExist(err) {
				return nil
			}
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

		err = p.Signal(unix.SIGKILL)
		if err != nil {
			if processNotExist(err) {
				return nil
			}
			maybeSetExitCode(exitDinitFailure, err)
			return err
		}

		return nil
	})

	// By waiting we are also making sure that dinit does not exit before
	// this reparented child process exits.
	return doWait(p, name, stage)
}
