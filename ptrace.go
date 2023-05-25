package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	ERESTARTSYS    = unix.Errno(512)
	ERESTARTNOINTR = unix.Errno(513)
	ERESTARTNOHAND = unix.Errno(514)
)

const maxErrno = uint64(0xfffffffffffff001)

const (
	dataSize    = 1024
	controlSize = 1024
	memorySize  = 4096
)

var errorReturn = -1

// Call a syscall and a breakpoint.
var syscallInstruction = [...]byte{0x0F, 0x05, 0xCC}

// Do not wrap an error if both errors are not nil.
func errorsJoin(err1, err2 error) error {
	if err1 == nil {
		return err2
	} else if err2 == nil {
		return err1
	}
	return errors.Join(err1, err2)
}

type PtraceTracee struct {
	Pid           int
	memoryAddress uint64
}

func (t *PtraceTracee) Attach() error {
	if t.memoryAddress != 0 {
		return fmt.Errorf("tracee already attached")
	}

	err := unix.PtraceSeize(t.Pid)
	if err != nil {
		return fmt.Errorf("ptrace seize: %w", err)
	}

	err = unix.PtraceInterrupt(t.Pid)
	if err != nil {
		err = fmt.Errorf("ptrace interrupt: %w", err)
		err2 := unix.PtraceDetach(t.Pid)
		return errorsJoin(err, err2)
	}

	err = t.waitTrap(unix.PTRACE_EVENT_STOP)
	if err != nil {
		err2 := unix.PtraceDetach(t.Pid)
		return errorsJoin(err, err2)
	}

	address, err := t.allocateMemory()
	if err != nil {
		err2 := unix.PtraceDetach(t.Pid)
		return errorsJoin(err, err2)
	}

	t.memoryAddress = address

	return nil
}

func (t *PtraceTracee) Detach() error {
	if t.memoryAddress == 0 {
		return fmt.Errorf("tracee not attached")
	}

	err := t.freeMemory(t.memoryAddress)
	if err != nil {
		err2 := unix.PtraceDetach(t.Pid)
		if err2 == nil {
			t.memoryAddress = 0
		}
		return errorsJoin(err, err2)
	}

	err = unix.PtraceDetach(t.Pid)
	if err != nil {
		return fmt.Errorf("ptrace detach: %w", err)
	}

	t.memoryAddress = 0

	return nil
}

func (t *PtraceTracee) Dup2(hostFd int, traceeFd int) (err error) {
	if t.memoryAddress == 0 {
		return fmt.Errorf("tracee not attached")
	}

	addr := fmt.Sprintf("@dinit-%s.sock", uuid.NewString())
	listen, err := net.Listen("unix", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listen.Close()

	traceeSocket, err := t.sysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		err2 := t.sysClose(traceeSocket)
		err = errorsJoin(err, err2)
	}()

	err = t.sysConnectUnix(traceeSocket, addr)
	if err != nil {
		return err
	}

	connection, err := listen.Accept()
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is %T and not net.UnixConn", connection)
	}

	// Encode the file descriptor.
	rights := unix.UnixRights(hostFd)
	// Send it over. Write always returns error on short writes.
	// We send one byte data just to be sure it gets through.
	_, _, err = unixConnection.WriteMsgUnix([]byte{0}, rights, nil)
	if err != nil {
		return err
	}

	p := make([]byte, dataSize)
	oob := make([]byte, controlSize)
	// TODO: What to do on short reads?
	_, oobn, _, err := t.sysRecvmsgUnix(traceeSocket, p, oob, 0)
	if err != nil {
		return err
	}

	// The buffer might not been used fully.
	oob = oob[:oobn]

	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("ParseSocketControlMessage: %w", err)
	}

	fds, err := unix.ParseUnixRights(&cmsgs[0])
	if err != nil {
		return fmt.Errorf("ParseUnixRights: %w", err)
	}

	fd := fds[0]

	err = t.sysDup2(fd, traceeFd)
	if err != nil {
		return err
	}

	err = t.sysClose(fd)
	if err != nil {
		return err
	}

	return nil
}

func (t *PtraceTracee) allocateMemory() (uint64, error) {
	addr, err := t.doSyscall(false, unix.SYS_MMAP, func(start uint64) ([]byte, [6]uint64, error) {
		fd := -1
		return nil, [6]uint64{
			0,          // addr
			memorySize, // length
			unix.PROT_EXEC | unix.PROT_READ | unix.PROT_WRITE, // prot
			unix.MAP_PRIVATE | unix.MAP_ANONYMOUS,             // flags
			uint64(fd),                                        // fd
			0,                                                 // offset
		}, nil
	})
	if err != nil {
		err = fmt.Errorf("allocate memory: %w", err)
	}
	return addr, err
}

func (t *PtraceTracee) freeMemory(address uint64) error {
	_, err := t.doSyscall(false, unix.SYS_MUNMAP, func(start uint64) ([]byte, [6]uint64, error) {
		return nil, [6]uint64{
			address,    // addr
			memorySize, // length
		}, nil
	})
	if err != nil {
		err = fmt.Errorf("free memory: %w", err)
	}
	return err
}

func (t *PtraceTracee) sysSocket(domain, typ, proto int) (int, error) {
	fd, err := t.doSyscall(true, unix.SYS_SOCKET, func(start uint64) ([]byte, [6]uint64, error) {
		return nil, [6]uint64{
			uint64(domain), // domain
			uint64(typ),    // type
			uint64(proto),  // protocol
		}, nil
	})
	if err != nil {
		err = fmt.Errorf("sys socket: %w", err)
	}
	return int(fd), err
}

func (t *PtraceTracee) sysClose(fd int) error {
	_, err := t.doSyscall(true, unix.SYS_CLOSE, func(start uint64) ([]byte, [6]uint64, error) {
		return nil, [6]uint64{
			uint64(fd), // fd
		}, nil
	})
	if err != nil {
		err = fmt.Errorf("sys close: %w", err)
	}
	return err
}

func (t *PtraceTracee) sysDup2(oldFd, newFd int) error {
	_, err := t.doSyscall(true, unix.SYS_DUP2, func(start uint64) ([]byte, [6]uint64, error) {
		return nil, [6]uint64{
			uint64(oldFd), // oldfd
			uint64(newFd), // newfd
		}, nil
	})
	if err != nil {
		err = fmt.Errorf("sys dup2: %w", err)
	}
	return err
}

func (t *PtraceTracee) sysConnectUnix(fd int, path string) error {
	_, err := t.doSyscall(true, unix.SYS_CONNECT, func(start uint64) ([]byte, [6]uint64, error) {
		buf := new(bytes.Buffer)
		// We build unix.RawSockaddrUnix in the buffer.
		// Family field.
		err := binary.Write(buf, binary.LittleEndian, uint16(unix.AF_UNIX))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		p := []byte(path)
		abstract := false
		// If it starts with @, it is an abstract unix domain socket.
		// We change @ to a null character.
		if p[0] == '@' {
			p[0] = 0
			abstract = true
		} else if p[0] == 0 {
			abstract = true
		}
		// Path field.
		err = binary.Write(buf, binary.LittleEndian, p)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		if !abstract {
			// If not abstract, then write a null character.
			err = binary.Write(buf, binary.LittleEndian, uint8(0))
			if err != nil {
				return nil, [6]uint64{}, err
			}
		}
		// Sanity check.
		if uint64(buf.Len()) > uint64(unsafe.Sizeof(unix.RawSockaddrUnix{})) {
			return nil, [6]uint64{}, fmt.Errorf("path too long")
		}
		payload := buf.Bytes()
		return payload, [6]uint64{uint64(fd), start, uint64(len(payload))}, nil
	})
	if err != nil {
		err = fmt.Errorf("sys connect unix: %w", err)
	}
	return err
}

func (t *PtraceTracee) sysRecvmsgUnix(fd int, p, oob []byte, flags int) (int, int, int, error) {
	var payload []byte
	res, err := t.doSyscall(true, unix.SYS_RECVMSG, func(start uint64) ([]byte, [6]uint64, error) {
		buf := new(bytes.Buffer)
		// We build unix.Iovec.Base in the buffer.
		err := binary.Write(buf, binary.LittleEndian, p)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// We build unix.Msghdr.Control in the buffer.
		err = binary.Write(buf, binary.LittleEndian, oob)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// We build unix.Iovec in the buffer.
		// Base field.
		err = binary.Write(buf, binary.LittleEndian, uint64(start))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Len field.
		err = binary.Write(buf, binary.LittleEndian, uint64(len(p)))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		offset := uint64(buf.Len())
		// We build unix.Msghdr in the buffer.
		// Name field. Null pointer.
		err = binary.Write(buf, binary.LittleEndian, uint64(0))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Namelen field.
		err = binary.Write(buf, binary.LittleEndian, uint32(0))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Pad_cgo_0 field.
		err = binary.Write(buf, binary.LittleEndian, [4]byte{})
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Iov field.
		err = binary.Write(buf, binary.LittleEndian, start+uint64(len(p))+uint64(len(oob)))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Iovlen field.
		err = binary.Write(buf, binary.LittleEndian, uint64(1))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Control field.
		err = binary.Write(buf, binary.LittleEndian, start+uint64(len(p)))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Controllen field.
		err = binary.Write(buf, binary.LittleEndian, uint64(len(oob)))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Flags field.
		err = binary.Write(buf, binary.LittleEndian, int32(0))
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Pad_cgo_1 field.
		err = binary.Write(buf, binary.LittleEndian, [4]byte{})
		if err != nil {
			return nil, [6]uint64{}, err
		}
		// Sanity check.
		if uint64(buf.Len())-offset != uint64(unsafe.Sizeof(unix.Msghdr{})) {
			panic(fmt.Errorf("Msghdr in buffer does not match the size of Msghdr"))
		}
		payload = buf.Bytes()
		return payload, [6]uint64{
			uint64(fd),     // sockfd
			start + offset, // msg
			0,              // flags
		}, nil
	})
	if err != nil {
		return int(res), 0, 0, fmt.Errorf("sys recvmsg unix: %w", err)
	}
	buf := bytes.NewReader(payload)
	err = binary.Read(buf, binary.LittleEndian, p) // unix.Iovec.Base
	if err != nil {
		return int(res), 0, 0, fmt.Errorf("sys recvmsg unix: %w", err)
	}
	err = binary.Read(buf, binary.LittleEndian, oob) // unix.Msghdr.Control
	if err != nil {
		return int(res), 0, 0, fmt.Errorf("sys recvmsg unix: %w", err)
	}
	_, _ = io.CopyN(io.Discard, buf, 8) // unix.Iovec.Base field.
	_, _ = io.CopyN(io.Discard, buf, 8) // unix.Iovec.Len field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Name field.
	_, _ = io.CopyN(io.Discard, buf, 4) // Namelen field.
	_, _ = io.CopyN(io.Discard, buf, 4) // Pad_cgo_0 field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Iov field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Iovlen field.
	_, _ = io.CopyN(io.Discard, buf, 8) // Control field.
	var oobn uint64
	err = binary.Read(buf, binary.LittleEndian, &oobn) // Controllen field.
	if err != nil {
		return int(res), 0, 0, fmt.Errorf("sys recvmsg unix: %w", err)
	}
	var recvflags int32
	err = binary.Read(buf, binary.LittleEndian, &recvflags) // Flags field.
	if err != nil {
		return int(res), 0, 0, fmt.Errorf("sys recvmsg unix: %w", err)
	}
	return int(res), int(oobn), int(recvflags), nil
}

func (t *PtraceTracee) syscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, error)) (result uint64, err error) {
	var originalRegs unix.PtraceRegs
	err = unix.PtraceGetRegs(t.Pid, &originalRegs)
	if err != nil {
		err = fmt.Errorf("ptrace getregs: %w", err)
		return uint64(errorReturn), err
	}

	var start uint64
	var payload []byte
	var arguments [6]uint64
	var originalInstructions []byte
	if useMemory {
		start = t.memoryAddress
		payload, arguments, err = args(t.memoryAddress)
		if err != nil {
			return uint64(errorReturn), err
		}
		availableMemory := memorySize - len(syscallInstruction)
		if len(payload) > availableMemory {
			return uint64(errorReturn), fmt.Errorf("syscall payload (%d B) is larger than available memory (%d B)", len(payload), availableMemory)
		}
	} else {
		// TODO: What happens if Rip is not 64bit aligned?
		start = originalRegs.Rip
		payload, arguments, err = args(start)
		if err != nil {
			return uint64(errorReturn), err
		}

		// TODO: What if payload is so large that it hits the end of the data section?
		originalInstructions, err = t.readData(uintptr(start), len(payload)+len(syscallInstruction))
		if err != nil {
			return uint64(errorReturn), err
		}
	}

	defer func() {
		err2 := unix.PtraceSetRegs(t.Pid, &originalRegs)
		err = errorsJoin(err, err2)
	}()

	if !useMemory {
		defer func() {
			err2 := t.writeData(uintptr(start), originalInstructions)
			err = errorsJoin(err, err2)
		}()
	}

	err = t.writeData(uintptr(start), payload)
	if err != nil {
		return uint64(errorReturn), err
	}

	instructionPointer := start + uint64(len(payload))
	err = t.writeData(uintptr(instructionPointer), syscallInstruction[:])
	if err != nil {
		return uint64(errorReturn), err
	}

	var resultRegs unix.PtraceRegs
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
	if err != nil {
		err = fmt.Errorf("ptrace setregs: %w", err)
		return uint64(errorReturn), err
	}

	err = t.runToBreakpoint()
	if err != nil {
		return uint64(errorReturn), err
	}

	err = unix.PtraceGetRegs(t.Pid, &resultRegs)
	if err != nil {
		err = fmt.Errorf("ptrace getregs: %w", err)
		return uint64(errorReturn), err
	}

	if resultRegs.Rax > maxErrno {
		return uint64(errorReturn), unix.Errno(-resultRegs.Rax)
	}

	newPayload, err := t.readData(uintptr(start), len(payload))
	if err != nil {
		return uint64(errorReturn), err
	}
	copy(payload, newPayload)

	return resultRegs.Rax, nil
}

func (t *PtraceTracee) doSyscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, error)) (uint64, error) {
	for {
		result, err := t.syscall(useMemory, call, args)
		if err != nil {
			if errors.Is(err, ERESTARTSYS) {
				continue
			} else if errors.Is(err, ERESTARTNOINTR) {
				continue
			} else if errors.Is(err, ERESTARTNOHAND) {
				continue
			} else if errors.Is(err, unix.EINTR) {
				continue
			}
			// Go to return.
		}

		return result, err
	}
}

func (t *PtraceTracee) readData(address uintptr, length int) ([]byte, error) {
	data := make([]byte, length)
	n, err := unix.PtracePeekData(t.Pid, address, data)
	if err != nil {
		err = fmt.Errorf("ptrace peekdata: %w", err)
		return nil, err
	}
	if n != length {
		return nil, fmt.Errorf("wanted to read %d bytes, but read %d bytes", length, n)
	}
	return data, nil
}

func (t *PtraceTracee) writeData(address uintptr, data []byte) error {
	n, err := unix.PtracePokeData(t.Pid, address, data)
	if err != nil {
		err = fmt.Errorf("ptrace pokedata: %w", err)
		return err
	}
	if n != len(data) {
		return fmt.Errorf("wanted to write %d bytes, but wrote %d bytes", len(data), n)
	}
	return nil
}

func (t *PtraceTracee) runToBreakpoint() error {
	err := unix.PtraceCont(t.Pid, 0)
	if err != nil {
		return fmt.Errorf("run to breakpoint: %w", err)
	}

	// 0 trap cause means a breakpoint or single stepping.
	return t.waitTrap(0)
}

func (t *PtraceTracee) waitTrap(cause int) error {
	for {
		var status unix.WaitStatus
		var err error
		for {
			_, err = unix.Wait4(t.Pid, &status, 0, nil)
			if err == nil || !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("wait trap: %w", err)
		}
		if status.TrapCause() == cause {
			return nil
		} else if status.Stopped() {
			if status.StopSignal() == unix.SIGTRAP {
				logWarnf("unexpected trap cause for PID %d: %d, expected %d", t.Pid, status.TrapCause(), cause)
				return nil
			}
			// We pass all other signals on to the tracee.
			err := unix.PtraceCont(t.Pid, int(status.StopSignal()))
			if err != nil {
				return fmt.Errorf("wait trap: ptrace cont with %d: %w", int(status.StopSignal()), err)
			}
			continue
		}
		return fmt.Errorf("wait trap: unexpected wait status after wait, exit status %d, signal %d, stop signal %d, trap cause %d, expected trap cause %d", status.ExitStatus(), status.Signal(), status.StopSignal(), status.TrapCause(), cause)
	}
}

func ptraceRedirectStdoutStderr(pid int) (stdout, stderr *os.File, err error) {
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
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
	defer stdoutWriter.Close()
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
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
		err = errorsJoin(err, err2)
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
