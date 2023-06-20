package dinit_test

import (
	"bytes"
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"gitlab.com/tozd/dinit/internal/dinit"
)

func TestReparentingTerminate(t *testing.T) {
	var buf bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(writer)
	})

	dinit.ConfigureLog("debug")

	cmd := exec.Command("/bin/sleep", "infinity")
	e := cmd.Start()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	g, ctx := errgroup.WithContext(context.Background())

	dinit.ProcessPid(ctx, g, dinit.ReparentingTerminate, cmd.Process.Pid)

	e = g.Wait()
	require.NoError(t, e)

	lines := strings.Split(buf.String(), "\n")
	require.Len(t, lines, 4)
	assert.Regexp(t, `.+Z dinit: warning: sleep/\d+: terminating reparented child process with PID \d+(: /bin/sleep infinity)?`, lines[0])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`, lines[1])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`, lines[2])
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
