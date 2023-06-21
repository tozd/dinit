package dinit_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"gitlab.com/tozd/dinit/internal/dinit"
)

func withLogger(t *testing.T, l *log.Logger, f func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	defer reader.Close() //nolint:staticcheck
	// We might double close writer here, but that is OK and we ignore any error.
	defer writer.Close()
	require.NoError(t, err)
	orgWriter := l.Writer()
	l.SetOutput(writer)
	defer func() {
		l.SetOutput(orgWriter)
	}()

	var wg sync.WaitGroup
	var data []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		data, _ = io.ReadAll(reader)
	}()
	dinit.ConfigureLog("info")
	f()
	writer.Close()
	wg.Wait()
	return string(data)
}

func assertLogs(t *testing.T, expected []string, actual string, msgAndArgs ...interface{}) {
	t.Helper()

	lines := strings.Split(actual, "\n")
	require.Len(t, lines, len(expected)+1)
	assert.Equal(t, "", lines[len(lines)-1])

	rs := []*regexp.Regexp{}
	for _, r := range expected {
		rs = append(rs, regexp.MustCompile(r))
	}

	for _, line := range lines[:len(lines)-1] {
		match := -1
		for i, r := range rs {
			if r.MatchString(line) {
				match = i
				break
			}
		}
		if match != -1 {
			// Remove regexp at index "match".
			rs = append(rs[:match], rs[match+1:]...)
			expected = append(expected[:match], expected[match+1:]...)
		} else {
			rxs := []string{}
			for _, r := range expected {
				rxs = append(rxs, fmt.Sprintf(`"%v"`, r))
			}
			assert.Fail(t, fmt.Sprintf("Expect \"%v\" to match one of %s", line, strings.Join(rxs, ", ")), msgAndArgs...)
		}
	}
}

func TestReparentingTerminate(t *testing.T) {
	dinit.MainContext, dinit.MainCancel = context.WithCancel(context.Background())

	l := withLogger(t, log.Default(), func() {
		cmd := exec.Command("/bin/sleep", "infinity")
		e := cmd.Start()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		// So that the command runs.
		time.Sleep(10 * time.Millisecond)

		g, ctx := errgroup.WithContext(dinit.MainContext)

		waiting := make(chan struct{})
		dinit.ProcessPid(ctx, g, dinit.ReparentingTerminate, cmd.Process.Pid, waiting)

		<-waiting

		e = g.Wait()
		require.NoError(t, e)
	})

	assertLogs(t, []string{
		`.+Z dinit: warning: sleep/\d+: terminating reparented child process with PID \d+(: /bin/sleep infinity)?`,
		`.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`,
		`.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`,
	}, l)
}

func TestReparentingAdoptCancel(t *testing.T) {
	dinit.MainContext, dinit.MainCancel = context.WithCancel(context.Background())

	l := withLogger(t, log.Default(), func() {
		cmd := exec.Command("/bin/sleep", "infinity")
		e := cmd.Start()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		// So that the command runs.
		time.Sleep(10 * time.Millisecond)

		ctx, cancel := context.WithCancel(dinit.MainContext)

		g, ctx := errgroup.WithContext(ctx)

		waiting := make(chan struct{})
		dinit.ProcessPid(ctx, g, dinit.ReparentingAdopt, cmd.Process.Pid, waiting)

		<-waiting

		cancel()

		e = g.Wait()
		require.ErrorAs(t, e, &context.Canceled)

		// So that the goroutine reading stdout and stderr from the process completes.
		time.Sleep(10 * time.Millisecond)
	})

	assertLogs(t, []string{
		`.+Z dinit: warning: sleep/\d+: adopting reparented child process with PID \d+(: /bin/sleep infinity)?`,
		`.+Z dinit: info: sleep/\d+: finishing`,
		`.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`,
		`.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`,
	}, l)
}

func TestReparentingAdoptFinish(t *testing.T) {
	dinit.MainContext, dinit.MainCancel = context.WithCancel(context.Background())

	l := withLogger(t, log.Default(), func() {
		stdin, stdinWriter, e := os.Pipe()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = stdin.Close()
			_ = stdinWriter.Close()
		})

		cmd := exec.Command("/bin/bash", "-c", "read; echo end")
		cmd.Stdin = stdin
		e = cmd.Start()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		// So that the command runs.
		time.Sleep(10 * time.Millisecond)

		g, ctx := errgroup.WithContext(dinit.MainContext)

		waiting := make(chan struct{})
		dinit.ProcessPid(ctx, g, dinit.ReparentingAdopt, cmd.Process.Pid, waiting)

		<-waiting

		_, _ = stdinWriter.WriteString("\n")

		e = g.Wait()
		require.NoError(t, e)

		// So that the goroutine reading stdout and stderr from the process completes.
		time.Sleep(10 * time.Millisecond)
	})

	assertLogs(t, []string{
		`.+Z dinit: warning: bash/\d+: adopting reparented child process with PID \d+(: /bin/bash -c read; echo end)?`,
		`.+Z dinit: warning: bash/\d+: not JSON stdout: end`,
		`.+Z dinit: info: bash/\d+: PID \d+ finished with status 0`,
	}, l)
}

func TestGetProcessInfo(t *testing.T) {
	for _, tt := range []struct {
		Cmd     []string
		Cmdline string
		Name    string
	}{
		{[]string{"/bin/bash", "-c", "sleep infinity"}, "sleep infinity", "sleep"},
		{[]string{"/bin/true"}, "", "true"},
		{[]string{"/bin/sleep", "infinity"}, "/bin/sleep infinity", "sleep"},
	} {
		t.Run(strings.Join(tt.Cmd, " "), func(t *testing.T) {
			cmd := exec.Command(tt.Cmd[0], tt.Cmd[1:]...)
			e := cmd.Start()
			require.NoError(t, e)
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			})

			// So that the command runs.
			time.Sleep(10 * time.Millisecond)

			cmdline, name, stage, err := dinit.GetProcessInfo(cmd.Process.Pid)
			assert.NoError(t, err)
			assert.Equal(t, tt.Cmdline, cmdline)
			assert.Equal(t, tt.Name, name)
			assert.Equal(t, strconv.Itoa(cmd.Process.Pid), stage)
		})
	}
}

func TestIsZombie(t *testing.T) {
	for _, tt := range []struct {
		Cmd    []string
		Zombie bool
	}{
		{[]string{"/bin/bash", "-c", "sleep infinity"}, false},
		{[]string{"/bin/true"}, true},
		{[]string{"/bin/sleep", "infinity"}, false},
	} {
		t.Run(strings.Join(tt.Cmd, " "), func(t *testing.T) {
			cmd := exec.Command(tt.Cmd[0], tt.Cmd[1:]...)
			e := cmd.Start()
			require.NoError(t, e)
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			})

			// So that the command runs.
			time.Sleep(10 * time.Millisecond)

			z, err := dinit.IsZombie(cmd.Process.Pid)
			assert.NoError(t, err)
			assert.Equal(t, tt.Zombie, z)
		})
	}
}

func TestRedirectJSON(t *testing.T) {
	l := withLogger(t, log.Default(), func() {
		var in bytes.Buffer
		var out bytes.Buffer
		in.WriteString(`{"test":"foo"}`)
		dinit.RedirectJSON("run", "test", []byte("test"), io.NopCloser(&in), &out)

		assert.Regexp(t, `\{"test":"foo","service":test,"stage":"run","logged":".+"\}`, out.String())
	})
	assert.Equal(t, "", l)

	l = withLogger(t, log.Default(), func() {
		var in bytes.Buffer
		var out bytes.Buffer
		in.WriteString(`test`)
		dinit.RedirectJSON("run", "test", []byte("test"), io.NopCloser(&in), &out)

		assert.Equal(t, "", out.String())
	})
	assert.Regexp(t, `\d+Z dinit: warning: test/run: not JSON stdout: test\n`, l)
}

func TestRedirectToLogWithPrefix(t *testing.T) {
	l := withLogger(t, log.Default(), func() {
		var in bytes.Buffer
		var out bytes.Buffer
		outLog := log.New(&out, "", 0)
		in.WriteString(`test`)
		dinit.RedirectToLogWithPrefix(outLog, "run", "test", "stdtest", io.NopCloser(&in))

		assert.Regexp(t, `.+Z test/run: test`, out.String())
	})
	assert.Equal(t, "", l)
}

func TestRunNoServices(t *testing.T) {
	dinit.MainContext, dinit.MainCancel = context.WithCancel(context.Background())

	l := withLogger(t, log.Default(), func() {
		dir := t.TempDir()
		g, ctx := errgroup.WithContext(dinit.MainContext)
		err := dinit.RunServices(ctx, g, dir)
		require.NoError(t, err)
		e := g.Wait()
		require.NoError(t, e)
	})
	assert.Regexp(t, `.+Z dinit: warning: no services found, exiting\n`, l)
}

func TestRunServices(t *testing.T) {
	t.Setenv("DINIT_JSON_STDOUT", "0")
	dinit.MainContext, dinit.MainCancel = context.WithCancel(context.Background())

	var stdout string
	stderr := withLogger(t, log.Default(), func() {
		stdout = withLogger(t, dinit.StdOutLog, func() {
			dir := t.TempDir()
			e := os.Mkdir(path.Join(dir, "service1"), 0o755)
			require.NoError(t, e)
			e = os.WriteFile(path.Join(dir, "service1", "run"), []byte("#!/bin/sh\necho start\n>&2 echo starterr\nexec sleep 1"), 0o755) //nolint:gosec
			require.NoError(t, e)
			e = os.Mkdir(path.Join(dir, "service2"), 0o755)
			require.NoError(t, e)
			e = os.WriteFile(path.Join(dir, "service2", "run"), []byte("#!/bin/sh\necho start\n>&2 echo starterr\nexec sleep infinity"), 0o755) //nolint:gosec
			require.NoError(t, e)
			e = os.WriteFile(path.Join(dir, "service2", "finish"), []byte("#!/bin/sh\necho end\n>&2 echo enderr\nkill -TERM $DINIT_PID"), 0o755) //nolint:gosec
			require.NoError(t, e)
			e = os.Mkdir(path.Join(dir, "service3"), 0o755)
			require.NoError(t, e)
			e = os.WriteFile(path.Join(dir, "service3", "run"), []byte("#!/bin/sh\necho start\n>&2 echo starterr\nexec sleep infinity"), 0o755) //nolint:gosec
			require.NoError(t, e)
			e = os.Mkdir(path.Join(dir, "service3", "log"), 0o755)
			require.NoError(t, e)
			e = os.WriteFile(path.Join(dir, "service3", "log", "run"), []byte("#!/bin/sh\necho log\n>&2 echo logerr\nexec cat"), 0o755) //nolint:gosec
			require.NoError(t, e)
			g, ctx := errgroup.WithContext(dinit.MainContext)
			err := dinit.RunServices(ctx, g, dir)
			require.NoError(t, err)
			e = g.Wait()
			require.NoError(t, e)

			// So that the goroutine reading stdout and stderr from the process completes.
			time.Sleep(10 * time.Millisecond)
		})
	})
	assertLogs(t, []string{
		`.+Z dinit: info: service1/run: starting`,
		`.+Z dinit: info: service3/run: starting`,
		`.+Z dinit: info: service2/run: starting`,
		`.+Z dinit: info: service1/run: running with PID \d+`,
		`.+Z dinit: info: service2/run: running with PID \d+`,
		`.+Z service1/run: starterr`,
		`.+Z dinit: info: service3/run: running with PID \d+`,
		`.+Z dinit: info: service3/log: starting`,
		`.+Z service2/run: starterr`,
		`.+Z dinit: info: service3/log: running with PID \d+`,
		`.+Z service3/run: starterr`,
		`.+Z service3/log: logerr`,
		`.+Z dinit: info: service1/run: PID \d+ finished with status 0`,
		`.+Z dinit: info: service2/run: finishing`,
		`.+Z dinit: info: service3/run: finishing`,
		`.+Z dinit: info: service3/run: sending SIGTERM to PID \d+`,
		`.+Z dinit: info: service3/run: PID \d+ finished with signal 15`,
		`.+Z dinit: info: service3/log: PID \d+ finished with status 0`,
		`.+Z dinit: info: service2/finish: running with PID \d+`,
		`.+Z service2/finish: enderr`,
		`.+Z dinit: info: service2/finish: PID \d+ finished with status 0`,
		`.+Z dinit: info: service2/run: PID \d+ finished with signal 15`,
	}, stderr)
	assertLogs(t, []string{
		`.+Z service1/run: start`,
		`.+Z service2/run: start`,
		`.+Z service3/run: log`,
		`.+Z service3/run: start`,
		`.+Z service2/finish: end`,
	}, stdout)
}
