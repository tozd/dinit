package dinit_test

import (
	"bytes"
	"context"
	"log"
	"os/exec"
	"strings"
	"testing"

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

	err := dinit.ReparentingTerminate(ctx, g, cmd.Process.Pid)
	require.NoError(t, err)

	lines := strings.Split(buf.String(), "\n")
	require.Len(t, lines, 4)
	assert.Regexp(t, `.+Z dinit: warning: sleep/\d+: terminating reparented child process with PID \d+(: /bin/sleep infinity)?`, lines[0])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: sending SIGTERM to PID \d+`, lines[1])
	assert.Regexp(t, `.+Z dinit: info: sleep/\d+: PID \d+ finished with signal 15`, lines[2])
	assert.Equal(t, "", lines[3])
}
