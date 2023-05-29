// We call maybeSetExitCode(1) early on an error and do not leave for error to
// first propagate and then set it, so that during cleanup while the error is
// propagating we do not set some other exit code first.

// We cannot use kcmp to compare file descriptors.
// See: https://github.com/moby/moby/issues/45621

// We cannot use pidfd_getfd to move file descriptors between processes.
// See: https://github.com/moby/moby/issues/45622

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const etcService = "/etc/service"

// We check for new reparented processes at a regular interval and trigger configured
// reparenting policy on them. Reparenting also happens on SIGCHLD signal so interval
// between reparenting checks can be shorter.
// By default docker stop waits for 10 seconds before it kills processes if container
// does not exit, so we want to detect any reparenting which might happen during shutdown
// and have time to send those processes SIGTERM as well. This can happen multiple times
// if terminating the first wave of reparented processes trigger another wave.
const reparentingInterval = time.Second

// How long to wait after SIGTERM to send SIGKILL to a reparented process?
const reparentingKillTimeout = 30 * time.Second

var procStatRegexp = regexp.MustCompile(`\((.*)\)`)

// TODO: Output milliseconds. See: https://github.com/golang/go/issues/60249
const logFlags = log.Ldate | log.Ltime | log.LUTC

type policyFunc = func(ctx context.Context, g *errgroup.Group, pid int) error

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

var mainContext context.Context
var mainCancel context.CancelFunc

func init() {
	mainContext, mainCancel = context.WithCancel(context.Background())
}

var mainPid = os.Getpid()

var exitCode *int = nil
var exitCodeMu sync.Mutex

func maybeSetExitCode(code int) {
	exitCodeMu.Lock()
	defer exitCodeMu.Unlock()
	if exitCode == nil {
		exitCode = &code
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
		// Nothing.
	default:
		logErrorf("invalid log level %s", level)
		os.Exit(1)
	}

	if pid := mainPid; pid != 1 {
		logInfof("not running as a PID 1, but PID %d, registering as a process subreaper", pid)
		// We are not running as PID 1 so we register ourselves as a process subreaper.
		_, _, errno := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_CHILD_SUBREAPER, 1, 0)
		if errno != 0 {
			logError(errno)
			os.Exit(1)
		}
	}

	go handleStopSignals()

	g, ctx := errgroup.WithContext(mainContext)

	switch policy := os.Getenv("DINIT_REPARENTING_POLICY"); policy {
	case "adopt":
		go reparenting(ctx, g, reparentingAdopt)
	case "terminate", "": // Default reparenting policy.
		go reparenting(ctx, g, reparentingTerminate)
	case "ignore":
	default:
		logErrorf("invalid reparenting policy %s", policy)
		// We haven't yet used the errgroup, so we can just exit.
		os.Exit(1)
	}

	g.Go(func() error {
		return runServices(ctx, g)
	})

	err := g.Wait()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			// Nothing.
		} else {
			maybeSetExitCode(1)
			logError(err)
		}
	}

	status := getExitCode()
	logInfof("dinit exiting with status %d", status)
	os.Exit(status)
}

func handleStopSignals() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, unix.SIGTERM, unix.SIGINT)
	for s := range c {
		if mainContext.Err() != nil {
			logInfof("got signal %d, already stopping children", s)
		} else {
			logInfof("got signal %d, stopping children", s)
			// Even if children complain being terminated, we still exit with 0.
			maybeSetExitCode(0)
			mainCancel()
		}
	}
}

var runningChildren = map[int]bool{}
var runningChildrenMu sync.RWMutex

func setRunningChildPid(pid int) {
	runningChildrenMu.Lock()
	defer runningChildrenMu.Unlock()
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

func runServices(ctx context.Context, g *errgroup.Group) error {
	entries, err := os.ReadDir(etcService)
	if err != nil {
		maybeSetExitCode(1)
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
			maybeSetExitCode(1)
			return err
		}
		// We skip anything which is not a directory.
		if !info.IsDir() {
			continue
		}
		g.Go(func() error {
			return runService(ctx, name, p)
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

func doWait(ctx context.Context, pid int, wait func() (*os.ProcessState, error), stage, name string, jsonName []byte, stdout, stderr *os.File) error {
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
			maybeSetExitCode(1)
			return fmt.Errorf("%s/%s: error waiting for the process: %w", name, stage, err)
		}
	} else {
		status = state.Sys().(syscall.WaitStatus)
	}

	if status.Exited() {
		if status.ExitStatus() != 0 {
			maybeSetExitCode(2)
		}
		logInfof("%s/%s: PID %d finished with status %d", name, stage, pid, status.ExitStatus())
	} else {
		// If process finished because of the signal but we have not been stopping it, we see it is as a process error.
		if ctx == nil || ctx.Err() == nil {
			maybeSetExitCode(2)
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
		maybeSetExitCode(1)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	cmd.Stderr = stderrWriter

	err = cmd.Start()

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
				if errors.Is(err, os.ErrProcessDone) {
					return nil
				}
				maybeSetExitCode(1)
				return err
			}

			return nil
		}
		maybeSetExitCode(1)
		return err
	}
	setRunningChildPid(cmd.Process.Pid)
	defer removeRunningChildPid(cmd.Process.Pid)

	logInfof("%s/stop: running with PID %d", name, cmd.Process.Pid)

	return doWait(nil, cmd.Process.Pid, func() (*os.ProcessState, error) {
		err := cmd.Wait()
		return cmd.ProcessState, err
	}, "stop", name, jsonName, stdout, stderr)
}

func runService(ctx context.Context, name, p string) error {
	logInfof("%s/run: starting", name)
	jsonName, err := json.Marshal(name)
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	r := path.Join(p, "run")
	cmd := exec.CommandContext(ctx, r)
	cmd.Dir = p
	cmd.Cancel = func() error {
		return stopService(cmd, name, jsonName, p)
	}

	// We do not use StdoutPipe and StderrPipe so that we can control when pipe is closed.
	// See: https://github.com/golang/go/issues/60309
	// See: https://go-review.googlesource.com/c/tools/+/484741
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	cmd.Stdout = stdoutWriter
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		// This will not be used.
		stdout.Close()
		stdoutWriter.Close()

		maybeSetExitCode(1)
		return err
	}
	cmd.Stderr = stderrWriter

	err = cmd.Start()

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
			maybeSetExitCode(1)
		}
		return err
	}
	setRunningChildPid(cmd.Process.Pid)
	defer removeRunningChildPid(cmd.Process.Pid)
	// When the service stops (which is when this function returns)
	// we stop all other services as well and exit ourselves.
	defer mainCancel()

	logInfof("%s/run: running with PID %d", name, cmd.Process.Pid)

	return doWait(ctx, cmd.Process.Pid, func() (*os.ProcessState, error) {
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
	g.Go(func() error {
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

// Even if the context is canceled we still continue processing reparented processes,
// but we force the policy to be reparentingTerminate to terminate reparented processes
// as soon as possible.
func reparenting(ctx context.Context, g *errgroup.Group, policy policyFunc) {
	// Processes get reparented to the main thread which has task ID matching PID.
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", mainPid, mainPid)
	done := ctx.Done()
	sigchild := make(chan os.Signal, 1)
	signal.Notify(sigchild, unix.SIGCHLD)
	ticker := time.NewTicker(reparentingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			// If the context is canceled, we just terminate any reparented process.
			policy = reparentingTerminate
			done = nil
			continue
		case <-sigchild:
		case <-ticker.C:
		}

		childrenData, err := os.ReadFile(childrenPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				logWarnf("unable to read process children from %s: %s", childrenPath, err)
			}
			continue
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, err := strconv.Atoi(childPid)
			if err != nil {
				logWarnf("failed to parse PID %s: %s", childPid, err)
				continue
			}
			if hasRunningChildPid(p) {
				// This is our own child.
			} else {
				// Unknown PID. We call configured policy.
				processPid(ctx, g, policy, p)
			}
		}
	}
}

func getProcessCommandLine(pid int) (string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		// This is an utility function, so we do not call maybeSetExitCode(1) here
		// but leave it to the caller to decide if and when to do so.
		return "", err
	}
	return string(bytes.ReplaceAll(cmdlineData, []byte("\x00"), []byte(" "))), nil
}

func getProcessProgramName(pid int) (string, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		// This is an utility function, so we do not call maybeSetExitCode(1) here
		// but leave it to the caller to decide if and when to do so.
		return "", err
	}
	match := procStatRegexp.FindSubmatch(statData)
	if len(match) != 2 {
		return "", fmt.Errorf("could not match program name in proc stat: %s", statData)
	}
	return string(match[1]), nil
}

func getProcessInfo(pid int) (string, string, string, error) {
	cmdline, err := getProcessCommandLine(pid)
	if err != nil {
		// This is an utility function, so we do not call maybeSetExitCode(1) here
		// but leave it to the caller to decide if and when to do so.
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
			// This is an utility function, so we do not call maybeSetExitCode(1) here
			// but leave it to the caller to decide if and when to do so.
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
		if errors.Is(err, os.ErrNotExist) {
			// Not a problem, process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if reparentingAdopt gets called multiple times,
			// it will just not do anything anymore.
			return nil
		}
		maybeSetExitCode(1)
		return err
	}
	jsonName, err := json.Marshal(name)
	if err != nil {
		maybeSetExitCode(1)
		return err
	}

	if cmdline != "" {
		logWarnf("%s/%s: adopting reparented child process with PID %d: %s", name, stage, pid, cmdline)
	} else {
		logWarnf("%s/%s: adopting reparented child process with PID %d", name, stage, pid)
	}

	setRunningChildPid(pid)
	defer removeRunningChildPid(pid)
	// When the process stops (which is when this function returns)
	// we stop all other services and exit ourselves.
	defer mainCancel()

	stdout, stderr, err := ptraceRedirectStdoutStderr(pid)
	if err != nil {
		logWarnf("%s/%s: error redirecting stdout and stderr: %s", name, stage, err)
	}

	p, _ := os.FindProcess(pid) // This call cannot fail.
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
				if errors.Is(err, os.ErrProcessDone) {
					return nil
				}
				maybeSetExitCode(1)
				return err
			}

			return ctx.Err()
		case <-done:
			// The process finished or there was an error waiting for it.
			// In any case we do not have anything to do anymore.
			return nil
		}
	})

	return doWait(ctx, pid, p.Wait, stage, name, jsonName, stdout, stderr)
}

// We do not care about context cancellation. Even if the context is canceled we still
// want to continue terminating reparented processes.
func reparentingTerminate(_ context.Context, g *errgroup.Group, pid int) error {
	cmdline, name, stage, err := getProcessInfo(pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not a problem, process does not exist anymore, we do not have to do anything about it anymore.
			// In this case it is OK if reparentingTerminate gets called multiple times,
			// it will just not do anything anymore.
			return nil
		}
		maybeSetExitCode(1)
		return err
	}

	if cmdline != "" {
		logWarnf("%s/%s: terminating reparented child process with PID %d: %s", name, stage, pid, cmdline)
	} else {
		logWarnf("%s/%s: terminating reparented child process with PID %d", name, stage, pid)
	}

	p, _ := os.FindProcess(pid) // This call cannot fail.
	done := make(chan struct{})
	defer close(done)

	g.Go(func() error {
		logInfof("%s/%s: sending SIGTERM to PID %d", name, stage, pid)

		err := p.Signal(unix.SIGTERM)
		if err != nil {
			if errors.Is(err, os.ErrProcessDone) {
				return nil
			}
			maybeSetExitCode(1)
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
			if errors.Is(err, os.ErrProcessDone) {
				return nil
			}
			maybeSetExitCode(1)
			return err
		}

		return nil
	})

	// By waiting we are also making sure that dinit does not exit before
	// this reparented child process exits.
	var status syscall.WaitStatus
	state, err := p.Wait()
	if err != nil {
		maybeSetExitCode(1)
		return fmt.Errorf("%s/%s: error waiting for the process: %w", name, stage, err)
	} else {
		status = state.Sys().(syscall.WaitStatus)
	}

	if status.Exited() {
		logInfof("%s/%s: PID %d finished with status %d", name, stage, pid, status.ExitStatus())
	} else {
		logInfof("%s/%s: PID %d finished with signal %d", name, stage, pid, status.Signal())
	}

	return nil
}
