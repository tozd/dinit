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
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const etcService = "/etc/service"

// TODO: Output milliseconds. See: https://github.com/golang/go/issues/60249
const logFlags = log.Ldate | log.Ltime | log.LUTC

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

// TODO: Expire old entries.
var reapedChildren = map[int]syscall.WaitStatus{}
var reapedChildrenMu sync.RWMutex

func getReapedChildWaitStatus(pid int) (syscall.WaitStatus, bool) {
	reapedChildrenMu.RLock()
	defer reapedChildrenMu.RUnlock()
	status, ok := reapedChildren[pid]
	return status, ok
}

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

	if pid := os.Getpid(); pid != 1 {
		logInfof("not running as a PID 1, but PID %d, registering as a process subreaper", pid)
		// We are not running as PID 1 so we register ourselves as a process subreaper.
		_, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, unix.PR_SET_CHILD_SUBREAPER, 1, 0)
		if err != 0 {
			logError(err)
			os.Exit(1)
		}
	}

	go handleSigChild()
	go handleStopSignals()

	g, ctx := errgroup.WithContext(mainContext)

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

func handleSigChild() {
	// We cannot just set SIGCHLD to SIG_IGN for kernel to reap zombies (and all children) for us,
	// because we have to store wait statuses for our own children.
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGCHLD)
	for range c {
		reapChildren()
	}
}

func reapChildren() {
	for {
		stop := func() bool {
			// We have to lock between wait call and updating reapedChildren so that it
			// does not happen that we the wait call was successful, but we have not yet
			// update the reapedChildren while another goroutine already failed in its
			// wait call and attempted to read from reapedChildren, failing there as well.
			reapedChildrenMu.Lock()
			defer reapedChildrenMu.Unlock()

			var status syscall.WaitStatus
			var pid int
			var err error
			for {
				pid, err = syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if err == nil || !errors.Is(err, syscall.EINTR) {
					break
				}
			}
			if errors.Is(err, syscall.ECHILD) {
				// We do not have any unwaited-for children.
				return true
			}
			if err != nil || pid == 0 {
				// There was some other error or call would block.
				return true
			}
			if status.Exited() {
				logInfof("reaped process with PID %d and status %d", pid, status.ExitStatus())
			} else {
				logInfof("reaped process with PID %d and signal %d", pid, status.Signal())
			}
			reapedChildren[pid] = status
			return false
		}()
		if stop {
			break
		}
	}
}

func handleStopSignals() {
	c := make(chan os.Signal, 3)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for range c {
		logInfo("got SIGTERM/SIGINT/SIGQUIT signal, stopping children")
		// Even if children complain being terminated, we still exit with 0.
		maybeSetExitCode(0)
		mainCancel()
	}
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

func redirectToLogWithPrefix(l *log.Logger, stage, name, input string, reader io.Reader) {
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
		logWarnf("error reading %s from %s/%s: %s", input, name, stage, err)
	}
}

func redirectStderrWithPrefix(stage, name string, reader io.Reader) {
	redirectToLogWithPrefix(log.Default(), stage, name, "stderr", reader)
}

func redirectStdoutWithPrefix(stage, name string, reader io.Reader) {
	redirectToLogWithPrefix(stdOutLog, stage, name, "stdout", reader)
}

func redirectJSON(stage, name string, jsonName []byte, reader io.Reader) {
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
					logWarnf("error writing stdout for %s/%s: %s", name, stage, err)
				}
			} else {
				logWarnf("not JSON stdout from %s/%s: %s\n", name, stage, line)
			}
		}
	}

	err := scanner.Err()
	// Reader can get closed and we ignore that.
	if err != nil && !errors.Is(err, os.ErrClosed) {
		logWarnf("error reading stdout from %s: %s", name, err)
	}
}

func cmdWait(ctx context.Context, cmd *exec.Cmd, stage, name string, jsonName []byte, stdout, stderr io.ReadCloser) error {
	go redirectStderrWithPrefix(stage, name, stderr)

	if os.Getenv("DINIT_JSON_STDOUT") == "0" {
		go redirectStdoutWithPrefix(stage, name, stdout)
	} else {
		go redirectJSON(stage, name, jsonName, stdout)
	}

	var status syscall.WaitStatus
	err := cmd.Wait()
	if err != nil {
		if errors.Is(err, syscall.ECHILD) {
			s, ok := getReapedChildWaitStatus(cmd.Process.Pid)
			if !ok {
				maybeSetExitCode(1)
				return fmt.Errorf("could not determine wait status of %s/%s", name, stage)
			}
			status = s
		} else if errors.Is(err, context.Canceled) {
			// If we are here, process finished successfully but the context has been canceled so err was set, so we just ignore the err.
			status = cmd.ProcessState.Sys().(syscall.WaitStatus)
		} else if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
			// This is a condition in Wait when err is set when process fails, so we just ignore the err.
			status = cmd.ProcessState.Sys().(syscall.WaitStatus)
		} else {
			maybeSetExitCode(1)
			return fmt.Errorf("error waiting for %s/%s: %w", name, stage, err)
		}
	} else {
		status = cmd.ProcessState.Sys().(syscall.WaitStatus)
	}

	if status.Exited() {
		if status.ExitStatus() != 0 {
			maybeSetExitCode(2)
		}
		logInfof("%s/%s with PID %d finished with status %d", name, stage, cmd.Process.Pid, status.ExitStatus())
	} else {
		// If process finished because of the signal but we have not been stopping it, we see it is as a process error.
		if ctx == nil || ctx.Err() == nil {
			maybeSetExitCode(2)
		}
		logInfof("%s/%s with PID %d finished with signal %d", name, stage, cmd.Process.Pid, status.Signal())
	}

	return nil
}

// We call maybeSetExitCode(1) early on an error and do not leave for error to
// first propagate and then set it, so that during cleanup while the error is
// propagating we do not set some other exit code first.
func stopService(runCmd *exec.Cmd, name string, jsonName []byte, p string) error {
	logInfof("stopping %s", name)
	r := path.Join(p, "stop")
	cmd := exec.Command(r)
	cmd.Dir = p
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	err = cmd.Start()
	if err != nil {
		// If stop program does not exist, we send SIGTERM instead.
		if errors.Is(err, os.ErrNotExist) {
			logInfof("sending SIGTERM to PID %d for %s", runCmd.Process.Pid, name)
			err := runCmd.Process.Signal(syscall.SIGTERM)
			if errors.Is(err, os.ErrProcessDone) {
				return nil
			}
			return err
		}
		maybeSetExitCode(1)
		return err
	}

	logInfof("%s/stop is running with PID %d", name, cmd.Process.Pid)

	return cmdWait(nil, cmd, "stop", name, jsonName, stdout, stderr)
}

// We call maybeSetExitCode(1) early on an error and do not leave for error to
// first propagate and then set it, so that during cleanup while the error is
// propagating we do not set some other exit code first.
func runService(ctx context.Context, name, p string) error {
	logInfof("starting %s", name)
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	err = cmd.Start()
	if err != nil {
		// Start can fail when context is canceled, but we do not want to set
		// the exit code because of the cancellation.
		if !errors.Is(err, context.Canceled) {
			maybeSetExitCode(1)
		}
		return err
	}
	// When the service stops (which is when this function returns)
	// we stop all other services as well and exit ourselves.
	defer mainCancel()

	logInfof("%s/run is running with PID %d", name, cmd.Process.Pid)

	return cmdWait(ctx, cmd, "run", name, jsonName, stdout, stderr)
}


	return nil
}
