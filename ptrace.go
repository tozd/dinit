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
	Pid      int
	attached bool
}

func (t *PtraceTracee) Attach() error {
	if t.attached {
		return fmt.Errorf("tracee already attached")
	}

	err := unix.PtraceSeize(t.Pid)
	if err != nil {
		return err
	}

	err = unix.PtraceInterrupt(t.Pid)
	if err != nil {
		unix.PtraceDetach(t.Pid)
		return err
	}

	t.attached = true

	return nil
}

func (t *PtraceTracee) Detach() error {
	if !t.attached {
		return fmt.Errorf("tracee not attached")
	}

	err := unix.PtraceDetach(t.Pid)
	if err != nil {
		return err
	}

	t.attached = false

	return nil
}

func (t *PtraceTracee) Dup2(hostFd int, traceeFd int) error {

}

func (t *PtraceTracee) syscall(call int, args ...any) (result uint64, err error) {
	if len(args) > 6 {
		panic(fmt.Errorf("too many arguments (%d) for a syscall", len(args)))
	}

	var originalRegs unix.PtraceRegs
	err = unix.PtraceGetRegs(t.Pid, &originalRegs)
	if err != nil {
		return 0, err
	}

	instructionPointer := originalRegs.Rip
	payload := []byte{}

	arguments := [6]uint64{}
	for i, arg := range args {
		switch a := arg.(type) {
		case []byte:
			payload = append(payload, a...)
			arguments[i] = instructionPointer
			instructionPointer += uint64(len(a))
		case string:
			payload = append(payload, a...)
			// Append null character.
			payload = append(payload, 0)
			arguments[i] = instructionPointer
			instructionPointer += uint64(len(a)) + 1
		case uint8:
			arguments[i] = uint64(a)
		case uint16:
			arguments[i] = uint64(a)
		case uint32:
			arguments[i] = uint64(a)
		case uint64:
			arguments[i] = uint64(a)
		case int8:
			arguments[i] = uint64(a)
		case int16:
			arguments[i] = uint64(a)
		case int32:
			arguments[i] = uint64(a)
		case int64:
			arguments[i] = uint64(a)
		case int:
			arguments[i] = uint64(a)
		case uint:
			arguments[i] = uint64(a)
		case uintptr:
			arguments[i] = uint64(a)
		default:
			panic(fmt.Errorf("invalid syscall argument %d: %T", i, a))
		}
	}

	// We do not change instructionPointer here, because it already
	// points to the beginning of appended instructions.
	payload = append(payload, syscallInstruction[:]...)

	// TODO: What if payload is so large that it hits the end of the data section?
	originalInstructions, err := t.readData(uintptr(originalRegs.Rip), len(payload))
	if err != nil {
		return 0, err
	}

	defer func() {
		err2 := unix.PtraceSetRegs(t.Pid, &originalRegs)
		if err == nil {
			err = err2
		}
	}()
	defer func() {
		err2 := t.writeData(uintptr(originalRegs.Rip), originalInstructions)
		if err == nil {
			err = err2
		}
	}()

	err = t.writeData(uintptr(originalRegs.Rip), payload)
	if err != nil {
		return 0, err
	}

	newRegs := originalRegs
	newRegs.Rip = instructionPointer
	newRegs.Rax = uint64(call)
	newRegs.Rdi = arguments[0]
	newRegs.Rsi = arguments[1]
	newRegs.Rdx = arguments[2]
	newRegs.R10 = arguments[3]
	newRegs.R8 = arguments[4]
	newRegs.R9 = arguments[5]

	err = unix.PtraceSetRegs(t.Pid, &newRegs)
	if err == nil {
		return 0, err
	}

	err = t.singleStep()
	if err == nil {
		return 0, err
	}

	var resultRegs unix.PtraceRegs
	err = unix.PtraceGetRegs(t.Pid, &resultRegs)
	if err != nil {
		return 0, err
	}

	if resultRegs.Rax > maxErrno {
		return uint64(errorReturn), syscall.Errno(-resultRegs.Rax)
	}

	return resultRegs.Rax, nil
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

	err = t.Dup2(int(stdoutWriter.Fd()), 1)
	if err != nil {
		return nil, nil, err
	}
	err = t.Dup2(int(stderrWriter.Fd()), 2)
	if err != nil {
		return nil, nil, err
	}

	return stdout, stderr, nil
}
