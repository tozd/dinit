package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxErrno = uint64(0xfffffffffffff001)

var errorReturn = -1
var syscallInstruction = [...]byte{0x0F, 0x05}

type PtraceTracee struct {
	Pid int
}

func (t *PtraceTracee) Attach() error {
	err := unix.PtraceSeize(t.Pid)
	if err != nil {
		return err
	}

	err = unix.PtraceInterrupt(t.Pid)
	if err != nil {
		unix.PtraceDetach(t.Pid)
		return err
	}

	return nil
}

func (t *PtraceTracee) Detach() error {
	return unix.PtraceDetach(t.Pid)
}

func (t *PtraceTracee) OpenSocket() error {

}

func (t *PtraceTracee) CloseSocket() error {

}

func (t *PtraceTracee) HijackFd(hostFd uintptr, traceeFd uintptr) error {

}

func (t *PtraceTracee) allocateMemory() error {

}

func (t *PtraceTracee) syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err error) {
	var originalRegs unix.PtraceRegs
	err = unix.PtraceGetRegs(t.Pid, &originalRegs)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		err2 := unix.PtraceSetRegs(t.Pid, &originalRegs)
		if err == nil {
			err = err2
		}
	}()

	originalInstructions, err := t.readData(uintptr(originalRegs.Rip), len(syscallInstruction))
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		err2 := t.writeData(uintptr(originalRegs.Rip), originalInstructions)
		if err == nil {
			err = err2
		}
	}()

	err = t.writeData(uintptr(originalRegs.Rip), syscallInstruction[:])
	if err != nil {
		return 0, 0, err
	}

	newRegs := originalRegs
	newRegs.Rax = uint64(trap)
	newRegs.Rdi = uint64(a1)
	newRegs.Rsi = uint64(a2)
	newRegs.Rdx = uint64(a3)
	newRegs.R10 = uint64(a4)
	newRegs.R8 = uint64(a5)
	newRegs.R9 = uint64(a6)

	err = unix.PtraceSetRegs(t.Pid, &newRegs)
	if err == nil {
		return 0, 0, err
	}

	err = t.singleStep()
	if err == nil {
		return 0, 0, err
	}

	var resultRegs unix.PtraceRegs
	err = unix.PtraceGetRegs(t.Pid, &resultRegs)
	if err != nil {
		return 0, 0, err
	}

	if resultRegs.Rax > maxErrno {
		return uintptr(errorReturn), 0, syscall.Errno(-resultRegs.Rax)
	}

	return uintptr(resultRegs.Rax), uintptr(resultRegs.Rdx), nil
}

func (t *PtraceTracee) readData(address uintptr, length int) ([]byte, error) {
	data := make([]byte, length)
	n, err := unix.PtracePeekData(t.Pid, address, data)
	if err != nil {
		return nil, err
	}
	if n != length {
		return nil, fmt.Errorf("PtraceTracee.readData wanted to read %d bytes, but read %d bytes", length, n)
	}
	return data, nil
}

func (t *PtraceTracee) writeData(address uintptr, data []byte) error {
	n, err := unix.PtracePokeData(t.Pid, address, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("PtraceTracee.writeData wanted to write %d bytes, but wrote %d bytes", len(data), n)
	}
	return nil
}

func (t *PtraceTracee) singleStep() error {
	err := unix.PtraceSingleStep(t.Pid)
	if err != nil {
		return err
	}

	return t.waitTrap()
}

func (t *PtraceTracee) waitTrap() error {
	var status unix.WaitStatus
	var err error
	for {
		_, err = unix.Wait4(t.Pid, &status, 0, nil)
		if err == nil || !errors.Is(err, unix.EINTR) {
			break
		}
	}
	// 0 trap cause means a breakpoint or single stepping.
	if status.TrapCause() != 0 {
		return fmt.Errorf("unexpected wait status after wait, exit status %d, signal %d, stop signal %d, trap cause %d", status.ExitStatus(), status.Signal(), status.StopSignal(), status.TrapCause())
	}
	return nil
}

func hijackStdoutStderr(pid int) (stdout *os.File, stderr *os.File, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	// Writer is not needed once it is (successfully or not) passed to the hijacked process.
	defer stdoutWriter.Close()
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	// Writer is not needed once it is (successfully or not) passed to the hijacked process.
	defer stderrWriter.Close()

	t := PtraceTracee{
		Pid: pid,
	}

	err = t.Attach()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		err2 := t.Detach()
		if err == nil {
			err = err2
		}
	}()

	err = t.OpenSocket()
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		err2 := t.CloseSocket()
		if err == nil {
			err = err2
		}
	}()

	err = t.HijackFd(stdout.Fd(), 1)
	if err != nil {
		return nil, nil, err
	}
	err = t.HijackFd(stderr.Fd(), 2)
	if err != nil {
		return nil, nil, err
	}

	return stdout, stderr, nil
}
