package dinit_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
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

func withLogger(t *testing.T, f func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	defer reader.Close() //nolint:staticcheck
	// We might double close writer here, but that is OK and we ignore any error.
	defer writer.Close()
	require.NoError(t, err)
	orgWriter := log.Writer()
	log.SetOutput(writer)
	defer func() {
		log.SetOutput(orgWriter)
	}()

	var wg sync.WaitGroup
	var l []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		l, _ = io.ReadAll(reader)
	}()
	dinit.ConfigureLog("info")
	f()
	writer.Close()
	wg.Wait()
	return string(l)
}

func TestReparentingTerminate(t *testing.T) {
	l := withLogger(t, func() {
		cmd := exec.Command("/bin/sleep", "infinity")
		e := cmd.Start()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		// So that the command runs.
		time.Sleep(10 * time.Millisecond)

		g, ctx := errgroup.WithContext(context.Background())

		dinit.ProcessPid(ctx, g, dinit.ReparentingTerminate, cmd.Process.Pid)

		e = g.Wait()
		require.NoError(t, e)
	})

	lines := strings.Split(l, "\n")
	require.Len(t, lines, 4)
	assert.Regexp(t, `.+Z dinit: warning: sleep/\d+: terminating reparented child process with PID \d+(: /bin/sleep infinity)?`, lines[0])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`, lines[1])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`, lines[2])
	assert.Equal(t, "", lines[3])
}

func TestReparentingAdoptCancel(t *testing.T) {
	l := withLogger(t, func() {
		cmd := exec.Command("/bin/sleep", "infinity")
		e := cmd.Start()
		require.NoError(t, e)
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})

		// So that the command runs.
		time.Sleep(10 * time.Millisecond)

		ctx, cancel := context.WithCancel(context.Background())

		g, ctx := errgroup.WithContext(ctx)

		dinit.ProcessPid(ctx, g, dinit.ReparentingAdopt, cmd.Process.Pid)

		// Time to adopt.
		time.Sleep(10 * time.Millisecond)

		cancel()

		e = g.Wait()
		require.ErrorAs(t, e, &context.Canceled)
	})

	lines := strings.Split(l, "\n")
	require.Len(t, lines, 5)
	assert.Regexp(t, `.+Z dinit: warning: sleep/\d+: adopting reparented child process with PID \d+(: /bin/sleep infinity)?`, lines[0])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: finishing`, lines[1])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`, lines[2])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`, lines[3])
	assert.Equal(t, "", lines[4])
}

func TestReparentingAdoptFinish(t *testing.T) {
	l := withLogger(t, func() {
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

		g, ctx := errgroup.WithContext(context.Background())

		dinit.ProcessPid(ctx, g, dinit.ReparentingAdopt, cmd.Process.Pid)

		// Time to adopt.
		time.Sleep(10 * time.Millisecond)

		_, _ = stdinWriter.WriteString("\n")

		e = g.Wait()
		require.NoError(t, e)
	})

	lines := strings.Split(l, "\n")
	require.Len(t, lines, 4)
	assert.Regexp(t, `.+Z dinit: warning: bash/\d+: adopting reparented child process with PID \d+(: /bin/bash -c read; echo end)?`, lines[0])
	assert.Regexp(t, `.+Z dinit: warning: bash/\d+: not JSON stdout: end`, lines[1])
	assert.Regexp(t, `.+Z dinit: info: bash/\d+: PID \d+ finished with status 0`, lines[2])
	assert.Equal(t, "", lines[3])
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
	l := withLogger(t, func() {
		var in bytes.Buffer
		var out bytes.Buffer
		in.WriteString(`{"test":"foo"}`)
		dinit.RedirectJSON("run", "test", []byte("test"), io.NopCloser(&in), &out)

		assert.Regexp(t, `\{"test":"foo","service":test,"stage":"run","logged":".+"\}`, out.String())
	})
	assert.Equal(t, "", l)

	l = withLogger(t, func() {
		var in bytes.Buffer
		var out bytes.Buffer
		in.WriteString(`test`)
		dinit.RedirectJSON("run", "test", []byte("test"), io.NopCloser(&in), &out)

		assert.Equal(t, "", out.String())
	})
	assert.Regexp(t, `\d+Z dinit: warning: test/run: not JSON stdout: test\n`, l)
}
