package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// TODO: Output milliseconds.
const logFlags = log.Ldate | log.Ltime | log.LUTC

var printInfo = os.Getenv("DINIT_LOG_INFO") == "1"

func logInfo(msg any) {
	if printInfo {
		log.Printf("dinit: info: %s", msg)
	}
}

func logInfof(msg string, args ...any) {
	if printInfo {
		log.Printf("dinit: info: "+msg, args...)
	}
}

func logWarn(msg any) {
	log.Printf("dinit: warning: %s", msg)
}

func logWarnf(msg string, args ...any) {
	log.Printf("dinit: warning: "+msg, args...)
}

func logError(msg any) {
	log.Printf("dinit: error: %s", msg)
}

func logErrorf(msg string, args ...any) {
	log.Printf("dinit: error: "+msg, args...)
}

var mainContext context.Context
var mainCancel context.CancelFunc

func init() {
	mainContext, mainCancel = context.WithCancel(context.Background())
}

// TODO: Expire old entries.
var reapedChildren = map[int]int{}
var reapedChildrenMu sync.Mutex

func setReapedChildExitStatus(pid, status int) {
	reapedChildrenMu.Lock()
	defer reapedChildrenMu.Unlock()
	reapedChildren[pid] = status
}

func getReapedChildExitStatus(pid int) (int, bool) {
	reapedChildrenMu.Lock()
	defer reapedChildrenMu.Unlock()
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

	code := runServices()
	logInfof("dinit stopping with exit status %d", code)
	os.Exit(code)
}

func handleSigChild() {
	// We cannot just set SIGCHLD to SIG_IGN for kernel to reap zombies (and all children) for us,
	// because we have to store exit statuses for our own children.
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGCHLD)
	for range c {
		reapChildren()
	}
}

func reapChildren() {
	for {
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
			return
		}
		if err != nil || pid == 0 {
			// There was some other error or call would block.
			return
		}
		logInfof("reaped process with PID %d and exit status %d", pid, status.ExitStatus())
		setReapedChildExitStatus(pid, status.ExitStatus())
	}
}

func handleStopSignals() {
	c := make(chan os.Signal, 3)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for range c {
		logInfo("got SIGTERM/SIGINT/SIGQUIT signal, stopping children")
		// Even if children complain being terminated, we still exit with 0.
		maybeSetExitCode(0)
		stopChildren()
	}
}

func stopChildren() {
	mainCancel()
}

func runServices() int {
	entries, err := os.ReadDir(etcService)
	if err != nil {
		logError(err)
		return 1
	}
	found := false
	errored := false
	g, ctx := errgroup.WithContext(mainContext)
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
			logError(err)
			stopChildren()
			errored = true
			break
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
		if !errored {
			logWarn("no services found")
		}
	} else {
		err := g.Wait()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Nothing.
			} else {
				maybeSetExitCode(1)
				logError(err)
			}
		}
	}

	return getExitCode()
}

func redirectToLogWithPrefix(l *log.Logger, stage, name string, reader io.Reader) {
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
		logWarnf("error reading stderr from %s/%s: %s", name, stage, err)
	}
}

func redirectToStderrWithPrefix(stage, name string, reader io.Reader) {
	redirectToLogWithPrefix(log.Default(), stage, name, reader)
}

func redirectToStdoutWithPrefix(stage, name string, reader io.Reader) {
	redirectToLogWithPrefix(stdOutLog, stage, name, reader)
}

func redirectJSONToStdout(stage, name string, jsonName []byte, reader io.Reader) {
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

func cmdWait(cmd *exec.Cmd, stage, name string, jsonName []byte, stdout, stderr io.ReadCloser) {
	go redirectToStderrWithPrefix(stage, name, stderr)

	if os.Getenv("DINIT_JSON_STDOUT") == "0" {
		go redirectToStdoutWithPrefix(stage, name, stdout)
	} else {
		go redirectJSONToStdout(stage, name, jsonName, stdout)
	}

	err := cmd.Wait()
	if err != nil {
		if errors.Is(err, syscall.ECHILD) {
			status, ok := getReapedChildExitStatus(cmd.Process.Pid)
			if !ok {
				maybeSetExitCode(1)
				logErrorf("could not determine exit status of %s/%s", name, stage)
			} else {
				if status != 0 {
					maybeSetExitCode(2)
				}
				logInfof("%s/%s with PID %d finished with exit status %d", name, stage, cmd.Process.Pid, status)
			}
		} else if errors.Is(err, context.Canceled) {
			// Nothing.
		} else if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
			maybeSetExitCode(2)
			logInfof("%s/%s with PID %d finished with exit status %d: %s", name, stage, cmd.Process.Pid, cmd.ProcessState.ExitCode())
		} else {
			maybeSetExitCode(1)
			logErrorf("error waiting for %s/%s: %s", name, stage, err)
		}
	} else {
		logInfof("%s/%s with PID %d finished with exit status %d", name, stage, cmd.Process.Pid, cmd.ProcessState.ExitCode())
	}
}

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
			_ = runCmd.Process.Signal(syscall.SIGTERM)
			return nil
		}
		maybeSetExitCode(1)
		return err
	}
	logInfof("%s/stop is running with PID %d", name, cmd.Process.Pid)

	cmdWait(cmd, "stop", name, jsonName, stdout, stderr)

	return nil
}

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
		maybeSetExitCode(1)
		return err
	}
	logInfof("%s/run is running with PID %d", name, cmd.Process.Pid)

	cmdWait(cmd, "run", name, jsonName, stdout, stderr)

	// The service stopped. We stop all other services as well.
	stopChildren()

	return nil
}
