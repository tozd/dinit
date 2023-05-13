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
)

const etcService = "/etc/service"

// From golang.org/x/sys/unix.
const PR_SET_CHILD_SUBREAPER = 0x24

func Warn(msg any) {
	log.Printf("dinit: warning: %s", msg)
}

func Warnf(msg string, args ...any) {
	log.Printf("dinit: warning: "+msg, args...)
}

func Error(msg any) {
	log.Printf("dinit: error: %s", msg)
}

func Errorf(msg string, args ...any) {
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

func main() {
	// TODO: Output milliseconds.
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	if pid := os.Getpid(); pid != 1 {
		// We are not running as PID 1 so we register ourselves as a process subreaper.
		_, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, PR_SET_CHILD_SUBREAPER, 1, 0)
		if err != 0 {
			Error(err)
			os.Exit(1)
		}
	}

	go handleSigChild()

	go handleStopSignals()

	os.Exit(runServices())
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
		setReapedChildExitStatus(pid, status.ExitStatus())
	}
}

func handleStopSignals() {
	c := make(chan os.Signal, 3)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for range c {
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
		Error(err)
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
			Error(err)
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
			Warn("no services found")
		}
	} else {
		err := g.Wait()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Nothing.
			} else {
				maybeSetExitCode(1)
				Error(err)
			}
		}
	}

	return getExitCode()
}

func redirectToStderrWithPrefix(name string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)

	res := true
	for res {
		res = scanner.Scan()
		line := scanner.Text()
		if len(line) > 0 {
			log.Printf("%s: %s\n", name, line)
		}
	}

	err := scanner.Err()
	// Reader can get closed and we ignore that.
	if err != nil && !errors.Is(err, os.ErrClosed) {
		Warnf("error reading stderr from %s: %s", name, err)
	}
}

func redirectJSONToStdout(name string, jsonName []byte, reader io.Reader) {
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
				buffer.WriteString(`,"logged":"`)
				buffer.Write(now.AppendFormat(timeBuffer, "2006-01-02T15:04:05.000Z07:00"))
				buffer.WriteString(`"}`)
				buffer.WriteString("\n")
				_, err := os.Stdout.Write(buffer.Bytes())
				if err != nil {
					Warnf("error writing stdout for %s: %s", name, err)
				}
			} else {
				Warnf("not JSON stdout from %s: %s\n", name, line)
			}
		}
	}

	err := scanner.Err()
	// Reader can get closed and we ignore that.
	if err != nil && !errors.Is(err, os.ErrClosed) {
		Warnf("error reading stdout from %s: %s", name, err)
	}
}

func runService(ctx context.Context, name, p string) error {
	jsonName, err := json.Marshal(name)
	if err != nil {
		maybeSetExitCode(1)
		return err
	}
	r := path.Join(p, "run")
	cmd := exec.CommandContext(ctx, r)
	cmd.Dir = p
	cmd.Cancel = func() error {
		// TODO: Call "stop".
		return nil
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

	go redirectToStderrWithPrefix(name, stderr)
	go redirectJSONToStdout(name, jsonName, stdout)

	err = cmd.Wait()
	if err != nil {
		if errors.Is(err, syscall.ECHILD) {
			status, ok := getReapedChildExitStatus(cmd.Process.Pid)
			if !ok {
				maybeSetExitCode(1)
				Errorf("could not determine exit status of %s", name)
			} else if status != 0 {
				maybeSetExitCode(2)
			}
		} else if errors.Is(err, context.Canceled) {
			// Nothing.
		} else if cmd.ProcessState != nil && !cmd.ProcessState.Success() {
			maybeSetExitCode(2)
		} else {
			maybeSetExitCode(1)
			Errorf("error waiting for %s: %s", name, err)
		}
	}

	// The service stopped. We stop all other services as well.
	stopChildren()

	return nil
}
