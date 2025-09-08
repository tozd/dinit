package pcontrol

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gitlab.com/tozd/go/errors"
	"golang.org/x/sys/unix"

	"gitlab.com/tozd/go/pcontrol"
)

// Redirects stdout and stderr of the process with PID pid to provided stdoutWriter and stderrWriter.
// Additionally, it copies original stdout and stderr (before redirect) from the process with PID to
// this process and returns them. Make sure to close them once you do not need them anymore.
func RedirectStdoutStderr( //nolint:nonamedreturns
	_ bool, logWarnf func(msg string, args ...any), pid int, stdoutWriter, stderrWriter *os.File,
) (stdout, stderr *os.File, err errors.E) {
	p := pcontrol.Process{
		Pid:        pid,
		MemorySize: pcontrol.DefaultMemorySize,
		LogWarnf:   logWarnf,
	}

	err = p.Attach()
	if err != nil {
		return stdout, stderr, err
	}
	defer func() {
		err2 := p.Detach()
		err = errors.Join(err, err2)
	}()

	fds, err := p.GetFds([]int{1, 2})
	if err != nil {
		// Some file descriptors might be retrieved, so we close them before returning.
		for _, fd := range fds {
			if fd != -1 {
				unix.Close(fd)
			}
		}
		return stdout, stderr, err
	}

	// When there is no error, number of file descriptors in fds should be the same
	// as file descriptors we gave to GetFds, but some might be -1, which we skip.
	if fds[0] != -1 {
		stdout = os.NewFile(uintptr(fds[0]), fmt.Sprintf("%d/stdout", pid))
		defer func() {
			if err != nil {
				stdout.Close()
				stdout = nil
			}
		}()
	}

	if fds[1] != -1 {
		stderr = os.NewFile(uintptr(fds[1]), fmt.Sprintf("%d/stderr", pid))
		defer func() {
			if err != nil {
				stderr.Close()
				stderr = nil
			}
		}()
	}

	err = p.SetFd(int(stdoutWriter.Fd()), 1)
	if err != nil {
		return stdout, stderr, err
	}
	err = p.SetFd(int(stderrWriter.Fd()), 2) //nolint:mnd
	if err != nil {
		return stdout, stderr, err
	}

	return stdout, stderr, err
}

// replaceFdForProcessFds copies traceeFds to this process to see which ones if any match
// "from". If match is found, we replace it with "to" by copying "to" to the tracee and set it
// instead of the corresponding traceeFd.
func replaceFdForProcessFds(_ bool, logWarnf func(msg string, args ...any), pid int, traceeFds []int, from, to *os.File) (err errors.E) { //nolint:nonamedreturns
	p := pcontrol.Process{
		Pid:        pid,
		MemorySize: pcontrol.DefaultMemorySize,
		LogWarnf:   logWarnf,
	}

	err = p.Attach()
	if err != nil {
		return err
	}
	defer func() {
		err2 := p.Detach()
		err = errors.Join(err, err2)
	}()

	hostFds, err := p.GetFds(traceeFds)
	// We close retrieved file descriptors no matter what on returning from this function.
	defer func() {
		for _, fd := range hostFds {
			if fd != -1 {
				unix.Close(fd)
			}
		}
	}()
	if err != nil {
		return err
	}

	// When there is no error, number of file descriptors in hostFds should be the same
	// as file descriptors in traceeFds, but some might be -1, which we skip. They can
	// be -1 because file descriptors might be closed since the time we enumerated them.
	for i, hostFd := range hostFds {
		if hostFd == -1 {
			continue
		}
		equal, e := pcontrol.EqualFds(hostFd, int(from.Fd()))
		if e != nil {
			return e
		}
		if !equal {
			continue
		}

		e = p.SetFd(int(to.Fd()), traceeFds[i])
		if e != nil {
			return e
		}
	}

	return err
}

// replaceFdForProcess enumerates all file descriptors the process with pid has and calls replaceFdForProcessFds
// with the list to see if any of enumerated file descriptors matches from. To do the matching we have to
// copy those file descriptors to this process. This is inherently racy so we are lenient if after enumeration
// we do not find some file descriptors from the list.
// TODO: This replaces only file descriptors for the whole process and not threads which called unshare.
func replaceFdForProcess(debugLog bool, logWarnf func(msg string, args ...any), pid int, from, to *os.File) errors.E {
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	entries, e := os.ReadDir(fdPath)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return errors.WithStack(e)
	}

	fds := []int{}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			errE := errors.WithMessage(e, "failed to parse fd")
			errors.Details(errE)["fd"] = entry.Name()
			return errE
		}
		fds = append(fds, fd)
	}

	return replaceFdForProcessFds(debugLog, logWarnf, pid, fds, from, to)
}

// A file descriptor we redirected in a direct children process might have been further inherited or
// duplicated. Because of that we copied the original file descriptor to this process (into from) and
// traverse the direct children and its descendants and search and replace for any copy of the file
// descriptor matching from, which we then replace with to. To do the matching we have to copy all file
// descriptors to this process. This is inherently racy as new children processes might be made after we
// have enumerated them. Because we replace file descriptors in the parent process before we go to its
// children we hope that any new children which are made while this function runs use replaced file descriptors.
func ReplaceFdForProcessAndChildren(debugLog bool, logWarnf func(msg string, args ...any), pid int, name string, from, to *os.File) errors.E {
	eq, err := pcontrol.EqualFds(int(from.Fd()), int(to.Fd()))
	if err != nil {
		return errors.WithMessage(err, "unable to compare file descriptors")
	}
	if eq {
		// Nothing to replace.
		return nil
	}

	err = replaceFdForProcess(debugLog, logWarnf, pid, from, to)
	if err != nil {
		if debugLog {
			logWarnf("error replacing %s fd for process with PID %d: % -+#.1v", name, pid, err)
		} else {
			logWarnf("error replacing %s fd for process with PID %d: %s", name, pid, err)
		}
	}

	taskPath := fmt.Sprintf("/proc/%d/task", pid)
	entries, e := os.ReadDir(taskPath)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		errE := errors.WithMessage(e, "unable to read process tasks")
		errors.Details(errE)["path"] = taskPath
		return errE
	}

	for _, entry := range entries {
		childrenPath := fmt.Sprintf("/proc/%d/task/%s/children", pid, entry.Name())
		childrenData, e := os.ReadFile(childrenPath)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			errE := errors.WithMessage(e, "unable to read process children")
			errors.Details(errE)["path"] = childrenPath
			return errE
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, e := strconv.Atoi(childPid)
			if e != nil {
				errE := errors.WithMessage(e, "failed to parse PID")
				errors.Details(errE)["pid"] = childPid
				return errE
			}
			err := ReplaceFdForProcessAndChildren(debugLog, logWarnf, p, name, from, to)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// The main function to setup redirect of stdout and stderr for a direct child.
// Moreover, for the direct child and all its descendants it also replaces all
// file descriptors matching those initial stdout and stderr with redirects as well.
func RedirectAllStdoutStderr(debugLog bool, logWarnf func(msg string, args ...any), pid int) (stdout, stderr *os.File, err errors.E) { //nolint:nonamedreturns
	defer func() {
		if err != nil {
			if stdout != nil {
				stdout.Close()
				stdout = nil
			}
			if stderr != nil {
				stderr.Close()
				stderr = nil
			}
		}
	}()

	stdout, stdoutWriter, e := os.Pipe()
	if e != nil {
		err = errors.WithStack(e)
		return stdout, stderr, err
	}
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
	defer stdoutWriter.Close()
	stderr, stderrWriter, e := os.Pipe()
	if e != nil {
		err = errors.WithStack(e)
		return stdout, stderr, err
	}
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
	defer stderrWriter.Close()

	originalStdout, originalStderr, err := RedirectStdoutStderr(debugLog, logWarnf, pid, stdoutWriter, stderrWriter)
	if err != nil {
		return stdout, stderr, err
	}
	if originalStdout != nil {
		defer originalStdout.Close()
	}
	if originalStderr != nil {
		defer originalStderr.Close()
	}

	if originalStdout != nil {
		err = ReplaceFdForProcessAndChildren(debugLog, logWarnf, pid, "stdout", originalStdout, stdoutWriter)
		if err != nil {
			return stdout, stderr, err
		}
	}

	if originalStderr != nil {
		err = ReplaceFdForProcessAndChildren(debugLog, logWarnf, pid, "stderr", originalStderr, stderrWriter)
		if err != nil {
			return stdout, stderr, err
		}
	}

	return stdout, stderr, err
}
