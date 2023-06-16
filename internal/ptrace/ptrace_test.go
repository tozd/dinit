package ptrace

import (
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMsghrd(t *testing.T) {
	p := []byte{1, 2, 3}
	oob := []byte{4, 5, 6}
	offset, p2, err := newMsghrd(42, p, oob)
	assert.NoError(t, err)
	assert.Equal(t, uint64(22), offset)
	assert.Equal(t, []byte{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x2a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2d, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0,
	}, p2)
}

func startProcess(t *testing.T) (*exec.Cmd, *os.File, *os.File, *os.File, *os.File, *os.File, *os.File, *os.File) {
	t.Helper()

	stdin, stdinWriter, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = stdinWriter.Close()
	})

	stdout1, stdoutWriter1, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdout1.Close()
		_ = stdoutWriter1.Close()
	})

	stderr1, stderrWriter1, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stderr1.Close()
		_ = stderrWriter1.Close()
	})

	stdout2, stdoutWriter2, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stdout2.Close()
		_ = stdoutWriter2.Close()
	})

	stderr2, stderrWriter2, e := os.Pipe()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = stderr2.Close()
		_ = stderrWriter2.Close()
	})

	cmd := exec.Command("/bin/bash", "-c", "read; echo end")
	cmd.Stdin = stdin
	cmd.Stdout = stdoutWriter1
	cmd.Stderr = stderrWriter1
	e = cmd.Start()
	require.NoError(t, e)

	return cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2
}

func TestReplaceFdForProcessFds(t *testing.T) {
	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	err := ReplaceFdForProcessFds(false, func(msg string, args ...any) {}, cmd.Process.Pid, []int{1}, stdoutWriter1, stdoutWriter2)
	require.NoError(t, err)

	_, _ = stdinWriter.WriteString("\n")

	_, _ = cmd.Process.Wait()
	waited = true

	_ = stdoutWriter1.Close()
	_ = stderrWriter1.Close()
	_ = stdoutWriter2.Close()
	_ = stderrWriter2.Close()

	sout, e := io.ReadAll(stdout2)
	require.NoError(t, e)

	serr, e := io.ReadAll(stderr2)
	require.NoError(t, e)

	assert.Equal(t, []byte("end\n"), sout)
	assert.Equal(t, []byte{}, serr)
}

func TestRedirectStdoutStderr(t *testing.T) {
	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	stdoutWriter3, stderrWriter3, err := RedirectStdoutStderr(false, func(msg string, args ...any) {}, cmd.Process.Pid, stdoutWriter2, stderrWriter2)
	t.Cleanup(func() {
		_ = stdoutWriter3.Close()
		_ = stderrWriter3.Close()
	})
	require.NoError(t, err)

	equal, err := equalFds(int(stdoutWriter1.Fd()), int(stdoutWriter3.Fd()))
	require.NoError(t, err)
	assert.True(t, equal)

	equal, err = equalFds(int(stderrWriter1.Fd()), int(stderrWriter3.Fd()))
	require.NoError(t, err)
	assert.True(t, equal)

	_, _ = stdinWriter.WriteString("\n")

	_, _ = cmd.Process.Wait()
	waited = true

	_ = stdoutWriter1.Close()
	_ = stderrWriter1.Close()
	_ = stdoutWriter2.Close()
	_ = stderrWriter2.Close()
	_ = stdoutWriter3.Close()
	_ = stderrWriter3.Close()

	sout, e := io.ReadAll(stdout2)
	require.NoError(t, e)

	serr, e := io.ReadAll(stderr2)
	require.NoError(t, e)

	assert.Equal(t, []byte("end\n"), sout)
	assert.Equal(t, []byte{}, serr)
}

func TestTracee(t *testing.T) {
	cmd := exec.Command("/usr/bin/sleep", "infinity")
	e := cmd.Start()
	require.NoError(t, e)
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	tracee := Tracee{
		Pid:      cmd.Process.Pid,
		DebugLog: false,
		LogWarnf: func(msg string, args ...any) {},
	}
	err := tracee.Attach()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, tracee.Detach())
	})

	pid, err := tracee.sysGetpid()
	require.NoError(t, err)
	assert.Equal(t, cmd.Process.Pid, pid)
}
