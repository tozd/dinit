package pcontrol_test

import (
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pc "gitlab.com/tozd/go/pcontrol"

	"gitlab.com/tozd/dinit/internal/pcontrol"
)

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

func TestReplaceFdForProcessAndChildren(t *testing.T) {
	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}

		_ = stdinWriter.Close()
		_ = stdoutWriter1.Close()
		_ = stderrWriter1.Close()
		_ = stdoutWriter2.Close()
		_ = stderrWriter2.Close()
		_ = stdout2.Close()
		_ = stderr2.Close()
	})

	err := pcontrol.ReplaceFdForProcessAndChildren(false, func(msg string, args ...any) {}, cmd.Process.Pid, "stdout", stdoutWriter1, stdoutWriter2)
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

		_ = stdinWriter.Close()
		_ = stdoutWriter1.Close()
		_ = stderrWriter1.Close()
		_ = stdoutWriter2.Close()
		_ = stderrWriter2.Close()
		_ = stdout2.Close()
		_ = stderr2.Close()
	})

	stdoutWriter3, stderrWriter3, err := pcontrol.RedirectStdoutStderr(false, func(msg string, args ...any) {}, cmd.Process.Pid, stdoutWriter2, stderrWriter2)
	t.Cleanup(func() {
		_ = stdoutWriter3.Close()
		_ = stderrWriter3.Close()
	})
	require.NoError(t, err)

	equal, err := pc.EqualFds(int(stdoutWriter1.Fd()), int(stdoutWriter3.Fd()))
	require.NoError(t, err)
	assert.True(t, equal)

	equal, err = pc.EqualFds(int(stderrWriter1.Fd()), int(stderrWriter3.Fd()))
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

func TestRedirectAllStdoutStderr(t *testing.T) {
	cmd, stdinWriter, stdoutWriter1, stderrWriter1, stdoutWriter2, stderrWriter2, stdout2, stderr2 := startProcess(t)

	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}

		_ = stdinWriter.Close()
		_ = stdoutWriter1.Close()
		_ = stderrWriter1.Close()
		_ = stdoutWriter2.Close()
		_ = stderrWriter2.Close()
		_ = stdout2.Close()
		_ = stderr2.Close()
	})

	stdout3, stderr3, err := pcontrol.RedirectAllStdoutStderr(false, func(msg string, args ...any) {}, cmd.Process.Pid)
	t.Cleanup(func() {
		_ = stdout3.Close()
		_ = stderr3.Close()
	})
	require.NoError(t, err)

	_, _ = stdinWriter.WriteString("\n")

	_, _ = cmd.Process.Wait()
	waited = true

	_ = stdoutWriter1.Close()
	_ = stderrWriter1.Close()
	_ = stdoutWriter2.Close()
	_ = stderrWriter2.Close()

	sout, e := io.ReadAll(stdout3)
	require.NoError(t, e)

	serr, e := io.ReadAll(stderr3)
	require.NoError(t, e)

	assert.Equal(t, []byte("end\n"), sout)
	assert.Equal(t, []byte{}, serr)
}
