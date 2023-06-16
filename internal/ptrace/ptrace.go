package ptrace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"gitlab.com/tozd/go/errors"
	"golang.org/x/sys/unix"
)

const (
	// These errno values are not really meant for user space programs (so they are not defined
	// in unix package) but we need them as we operate on a lower level and handle them in doSyscall.
	ERESTARTSYS    = unix.Errno(512)
	ERESTARTNOINTR = unix.Errno(513)
	ERESTARTNOHAND = unix.Errno(514)
)

// Errors are returned as negative numbers from syscalls but we compare them as uint64.
const maxErrno = uint64(0xfffffffffffff001)

const (
	dataSize    = 1024
	controlSize = 1024
	memorySize  = 4096
)

// We want to return -1 as uint64 so we need a variable to make Go happy.
var errorReturn = -1

// Call a syscall and a breakpoint. We do not use ptrace single step but ptrace cont
// until a breakpoint so that it is easier to allow signal handlers in tracee to run.
var syscallInstruction = [...]byte{0x0F, 0x05, 0xCC}

func newMsghrd(start uint64, p, oob []byte) (uint64, []byte, errors.E) {
	buf := new(bytes.Buffer)
	// We build unix.Iovec.Base in the buffer.
	e := binary.Write(buf, binary.LittleEndian, p)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Msghdr.Control in the buffer.
	e = binary.Write(buf, binary.LittleEndian, oob)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// We build unix.Iovec in the buffer.
	// Base field.
	e = binary.Write(buf, binary.LittleEndian, start)
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Len field.
	e = binary.Write(buf, binary.LittleEndian, uint64(len(p)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	offset := uint64(buf.Len())
	// We build unix.Msghdr in the buffer.
	// Name field. Null pointer.
	e = binary.Write(buf, binary.LittleEndian, uint64(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Namelen field.
	e = binary.Write(buf, binary.LittleEndian, uint32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_0 field.
	e = binary.Write(buf, binary.LittleEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iov field.
	e = binary.Write(buf, binary.LittleEndian, start+uint64(len(p))+uint64(len(oob)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Iovlen field.
	e = binary.Write(buf, binary.LittleEndian, uint64(1))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Control field.
	e = binary.Write(buf, binary.LittleEndian, start+uint64(len(p)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Controllen field.
	e = binary.Write(buf, binary.LittleEndian, uint64(len(oob)))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Flags field.
	e = binary.Write(buf, binary.LittleEndian, int32(0))
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Pad_cgo_1 field.
	e = binary.Write(buf, binary.LittleEndian, [4]byte{})
	if e != nil {
		return 0, nil, errors.WithStack(e)
	}
	// Sanity check.
	if uint64(buf.Len())-offset != uint64(unsafe.Sizeof(unix.Msghdr{})) {
		panic(errors.Errorf("Msghdr in buffer does not match the size of Msghdr"))
	}
	return offset, buf.Bytes(), nil
}

type Tracee struct {
	Pid           int
	memoryAddress uint64
	DebugLog      bool
	LogWarnf      func(msg string, args ...any)
}

// Attach attaches to the tracee and allocates private working memory in it.
func (t *Tracee) Attach() errors.E {
	if t.memoryAddress != 0 {
		return errors.Errorf("tracee already attached")
	}

	runtime.LockOSThread()

	err := errors.WithStack(unix.PtraceSeize(t.Pid))
	if err != nil {
		runtime.UnlockOSThread()
		return errors.Errorf("ptrace seize: %w", err)
	}

	err = errors.WithStack(unix.PtraceInterrupt(t.Pid))
	if err != nil {
		err = errors.Errorf("ptrace interrupt: %w", err)
		err2 := errors.WithStack(unix.PtraceDetach(t.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	err = t.waitTrap(unix.PTRACE_EVENT_STOP)
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(t.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	address, err := t.allocateMemory()
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(t.Pid))
		runtime.UnlockOSThread()
		return errors.Join(err, err2)
	}

	t.memoryAddress = address

	return nil
}

// Detach detaches from the tracee and frees the allocated private working memory in it.
func (t *Tracee) Detach() errors.E {
	if t.memoryAddress == 0 {
		return errors.Errorf("tracee not attached")
	}

	err := t.freeMemory(t.memoryAddress)
	if err != nil {
		err2 := errors.WithStack(unix.PtraceDetach(t.Pid))
		runtime.UnlockOSThread()
		if err2 == nil {
			t.memoryAddress = 0
		}
		return errors.Join(err, err2)
	}

	err = errors.WithStack(unix.PtraceDetach(t.Pid))
	runtime.UnlockOSThread()
	if err != nil {
		return errors.Errorf("ptrace detach: %w", err)
	}

	t.memoryAddress = 0

	return nil
}

// GetFds does a cross-process duplication of file descriptors from tracee into this process.
// It uses an abstract unix domain socket to get traceeFds from the tracee. If any of traceeFds
// are not found in the tracee, -1 is used in hostFds for it instead and no error is reported.
// You should close traceeFds afterwards if they are not needed anymore in the tracee.
func (t *Tracee) GetFds(traceeFds []int) (hostFds []int, err errors.E) {
	if t.memoryAddress == 0 {
		return nil, errors.Errorf("tracee not attached")
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, e := uuid.NewRandom()
	if e != nil {
		return nil, errors.WithStack(e)
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())

	traceeSocket, err := t.sysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err2 := t.sysClose(traceeSocket)
		err = errors.Join(err, err2)
	}()

	err = t.sysBindUnix(traceeSocket, addr)
	if err != nil {
		return nil, err
	}

	err = t.sysListen(traceeSocket, 1)
	if err != nil {
		return nil, err
	}

	connection, e := net.Dial("unix", addr)
	if e != nil {
		return nil, errors.Errorf("dial: %w", e)
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, errors.Errorf("connection is %T and not net.UnixConn", connection)
	}

	traceeConnection, err := t.sysAccept(traceeSocket, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		err2 := t.sysClose(traceeConnection)
		err = errors.Join(err, err2)
	}()

	for _, traceeFd := range traceeFds {
		// Encode the file descriptor.
		rights := unix.UnixRights(traceeFd)
		// Send it over. Write always returns error on short writes.
		// We send one byte data just to be sure everything gets through.
		_, _, err = t.sysSendmsg(traceeConnection, []byte{0}, rights, 0)
		if err != nil {
			if errors.Is(err, unix.EBADF) {
				hostFds = append(hostFds, -1)
				continue
			}
			return hostFds, err
		}

		// We could be more precise with needed sizes here, but it is good enough.
		p := make([]byte, dataSize)
		oob := make([]byte, controlSize)
		// TODO: What to do on short reads?
		_, oobn, _, _, e := unixConnection.ReadMsgUnix(p, oob)
		if e != nil {
			return hostFds, errors.WithStack(e)
		}

		// The buffer might not been used fully.
		oob = oob[:oobn]

		cmsgs, e := unix.ParseSocketControlMessage(oob)
		if e != nil {
			return hostFds, errors.Errorf("ParseSocketControlMessage: %w", e)
		}

		for _, cmsg := range cmsgs {
			// Break memory aliasing in for loop to make the linter happy.
			cmsg := cmsg
			fds, e := unix.ParseUnixRights(&cmsg)
			if e != nil {
				return hostFds, errors.Errorf("ParseUnixRights: %w", e)
			}

			hostFds = append(hostFds, fds...)
		}
	}

	return hostFds, nil
}

// SetFd does a cross-process duplication of a file descriptor from this process into tracee.
// It uses an abstract unix domain socket to send hostFd to the tracee and then dup2 syscall
// to set that file descriptor to traceeFd in the tracee (any previous traceeFd is closed
// by dup2). You should close hostFd afterwards if it is not needed anymore in this process.
func (t *Tracee) SetFd(hostFd int, traceeFd int) (err errors.E) {
	if t.memoryAddress == 0 {
		return errors.Errorf("tracee not attached")
	}

	// Address starting with @ signals that this is an abstract unix domain socket.
	u, e := uuid.NewRandom()
	if e != nil {
		return errors.WithStack(e)
	}
	addr := fmt.Sprintf("@dinit-%s.sock", u.String())
	listen, e := net.Listen("unix", addr)
	if e != nil {
		return errors.Errorf("listen: %w", e)
	}
	defer listen.Close()

	// SOCK_DGRAM did not work so we use SOCK_STREAM.
	// See: https://stackoverflow.com/questions/76327509/sending-a-file-descriptor-from-go-to-c
	traceeSocket, err := t.sysSocket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer func() {
		err2 := t.sysClose(traceeSocket)
		err = errors.Join(err, err2)
	}()

	err = t.sysConnectUnix(traceeSocket, addr)
	if err != nil {
		return err
	}

	connection, e := listen.Accept()
	if e != nil {
		return errors.Errorf("accept: %w", e)
	}
	defer connection.Close()

	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.Errorf("connection is %T and not net.UnixConn", connection)
	}

	// Encode the file descriptor.
	rights := unix.UnixRights(hostFd)
	// Send it over. Write always returns error on short writes.
	// We send one byte data just to be sure everything gets through.
	_, _, e = unixConnection.WriteMsgUnix([]byte{0}, rights, nil)
	if e != nil {
		return errors.WithStack(e)
	}

	// We could be more precise with needed sizes here, but it is good enough.
	p := make([]byte, dataSize)
	oob := make([]byte, controlSize)
	// TODO: What to do on short reads?
	_, oobn, _, err := t.sysRecvmsg(traceeSocket, p, oob, 0)
	if err != nil {
		return err
	}

	// The buffer might not been used fully.
	oob = oob[:oobn]

	cmsgs, e := unix.ParseSocketControlMessage(oob)
	if e != nil {
		return errors.Errorf("ParseSocketControlMessage: %w", e)
	}

	fds, e := unix.ParseUnixRights(&cmsgs[0])
	if e != nil {
		return errors.Errorf("ParseUnixRights: %w", e)
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

// Allocate private segment of memory in the tracee. We use it as
// the working memory for syscalls. Memory is configured to be
// executable as well and we store opcodes to run into it as well.
func (t *Tracee) allocateMemory() (uint64, errors.E) {
	addr, err := t.doSyscall(false, unix.SYS_MMAP, func(start uint64) ([]byte, [6]uint64, errors.E) {
		fd := -1
		return nil, [6]uint64{
			0,          // addr.
			memorySize, // length.
			unix.PROT_EXEC | unix.PROT_READ | unix.PROT_WRITE, // prot.
			unix.MAP_PRIVATE | unix.MAP_ANONYMOUS,             // flags.
			uint64(fd),                                        // fd.
			0,                                                 // offset.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("allocate memory: %w", err)
	}
	return addr, err
}

// Free private segment of memory in the tracee.
func (t *Tracee) freeMemory(address uint64) errors.E {
	_, err := t.doSyscall(false, unix.SYS_MUNMAP, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			address,    // addr.
			memorySize, // length.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("free memory: %w", err)
	}
	return err
}

// getpid syscall in the tracee.
func (t *Tracee) sysGetpid() (int, errors.E) {
	pid, err := t.doSyscall(true, unix.SYS_GETPID, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{}, nil
	})
	if err != nil {
		err = errors.Errorf("sys getpid: %w", err)
	}
	return int(pid), err
}

// socket syscall in the tracee.
func (t *Tracee) sysSocket(domain, typ, proto int) (int, errors.E) {
	fd, err := t.doSyscall(true, unix.SYS_SOCKET, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(domain), // domain.
			uint64(typ),    // type.
			uint64(proto),  // protocol.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys socket: %w", err)
	}
	return int(fd), err
}

// close syscall in the tracee.
func (t *Tracee) sysClose(fd int) errors.E {
	_, err := t.doSyscall(true, unix.SYS_CLOSE, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd), // fd.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys close: %w", err)
	}
	return err
}

// listen syscall in the tracee.
func (t *Tracee) sysListen(fd, backlog int) errors.E {
	_, err := t.doSyscall(true, unix.SYS_LISTEN, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),      // sockfd.
			uint64(backlog), // backlog.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys listen: %w", err)
	}
	return err
}

// accept syscall in the tracee.
func (t *Tracee) sysAccept(fd, flags int) (int, errors.E) {
	connFd, err := t.doSyscall(true, unix.SYS_ACCEPT4, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(fd),    // sockfd.
			0,             // addr.
			0,             // addrlen.
			uint64(flags), // flags.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys accept: %w", err)
	}
	return int(connFd), err
}

// dup2 syscall in the tracee.
func (t *Tracee) sysDup2(oldFd, newFd int) errors.E {
	_, err := t.doSyscall(true, unix.SYS_DUP2, func(start uint64) ([]byte, [6]uint64, errors.E) {
		return nil, [6]uint64{
			uint64(oldFd), // oldfd.
			uint64(newFd), // newfd.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys dup2: %w", err)
	}
	return err
}

// connect syscall in the tracee for AF_UNIX socket path. If path starts with @, it is replaced
// with null character to connect to an abstract unix domain socket.
func (t *Tracee) sysConnectUnix(fd int, path string) errors.E {
	return t.connectOrBindUnix(unix.SYS_CONNECT, "connect", fd, path)
}

// bind syscall in the tracee for AF_UNIX socket path. If path starts with @, it is replaced
// with null character to bind to an abstract unix domain socket.
func (t *Tracee) sysBindUnix(fd int, path string) errors.E {
	return t.connectOrBindUnix(unix.SYS_BIND, "bind", fd, path)
}

// Both connect and bind system calls take the same arguments, so we have one method for both.
func (t *Tracee) connectOrBindUnix(call int, name string, fd int, path string) errors.E {
	_, err := t.doSyscall(true, call, func(start uint64) ([]byte, [6]uint64, errors.E) {
		buf := new(bytes.Buffer)
		// We build unix.RawSockaddrUnix in the buffer.
		// Family field.
		e := binary.Write(buf, binary.LittleEndian, uint16(unix.AF_UNIX))
		if e != nil {
			return nil, [6]uint64{}, errors.WithStack(e)
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
		e = binary.Write(buf, binary.LittleEndian, p)
		if e != nil {
			return nil, [6]uint64{}, errors.WithStack(e)
		}
		if !abstract {
			// If not abstract, then write a null character.
			e = binary.Write(buf, binary.LittleEndian, uint8(0))
			if e != nil {
				return nil, [6]uint64{}, errors.WithStack(e)
			}
		}
		// Sanity check.
		if uint64(buf.Len()) > uint64(unsafe.Sizeof(unix.RawSockaddrUnix{})) {
			return nil, [6]uint64{}, errors.Errorf("path too long")
		}
		payload := buf.Bytes()
		return payload, [6]uint64{
			uint64(fd),           // sockfd.
			start,                // addr.
			uint64(len(payload)), // addrlen.
		}, nil
	})
	if err != nil {
		err = errors.Errorf("sys %s unix: %w", name, err)
	}
	return err
}

// sendmsg syscall in the tracee.
func (t *Tracee) sysSendmsg(fd int, p, oob []byte, flags int) (int, int, errors.E) {
	var payload []byte
	res, err := t.doSyscall(true, unix.SYS_SENDMSG, func(start uint64) ([]byte, [6]uint64, errors.E) {
		offset, pl, err := newMsghrd(start, p, oob)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		payload = pl
		return payload, [6]uint64{
			uint64(fd),     // sockfd.
			start + offset, // msg.
			uint64(flags),  // flags.
		}, nil
	})
	if err != nil {
		return int(res), 0, errors.Errorf("sys sendmsg: %w", err)
	}
	return int(res), len(oob), nil
}

// recvmsg syscall in the tracee.
//
//nolint:gomnd
func (t *Tracee) sysRecvmsg(fd int, p, oob []byte, flags int) (int, int, int, errors.E) {
	var payload []byte
	res, err := t.doSyscall(true, unix.SYS_RECVMSG, func(start uint64) ([]byte, [6]uint64, errors.E) {
		offset, pl, err := newMsghrd(start, p, oob)
		if err != nil {
			return nil, [6]uint64{}, err
		}
		payload = pl
		return payload, [6]uint64{
			uint64(fd),     // sockfd.
			start + offset, // msg.
			uint64(flags),  // flags.
		}, nil
	})
	if err != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", err)
	}
	buf := bytes.NewReader(payload)
	e := binary.Read(buf, binary.LittleEndian, p) // unix.Iovec.Base.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	e = binary.Read(buf, binary.LittleEndian, oob) // unix.Msghdr.Control.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
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
	e = binary.Read(buf, binary.LittleEndian, &oobn) // Controllen field.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	var recvflags int32
	e = binary.Read(buf, binary.LittleEndian, &recvflags) // Flags field.
	if e != nil {
		return int(res), 0, 0, errors.Errorf("sys recvmsg: %w", e)
	}
	return int(res), int(oobn), int(recvflags), nil
}

// Low-level call of a system call in the tracee. Use doSyscall instead.
// In almost all cases you want to use it with useMemory set to true to
// not change code of the tracee to run a syscall. (We use useMemory set
// to false only to obtain and free such memory.)
func (t *Tracee) syscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (result uint64, err errors.E) {
	if useMemory && t.memoryAddress == 0 {
		return uint64(errorReturn), errors.Errorf("syscall using memory is not possible without memory")
	}

	var originalRegs unix.PtraceRegs
	err = errors.WithStack(unix.PtraceGetRegs(t.Pid, &originalRegs))
	if err != nil {
		return uint64(errorReturn), errors.Errorf("ptrace getregs: %w", err)
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
			return uint64(errorReturn), errors.Errorf("syscall payload (%d B) is larger than available memory (%d B)", len(payload), availableMemory)
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
		err2 := errors.WithStack(unix.PtraceSetRegs(t.Pid, &originalRegs))
		err = errors.Join(err, err2)
	}()

	if !useMemory {
		defer func() {
			err2 := t.writeData(uintptr(start), originalInstructions)
			err = errors.Join(err, err2)
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

	err = errors.WithStack(unix.PtraceSetRegs(t.Pid, &newRegs))
	if err != nil {
		return uint64(errorReturn), errors.Errorf("ptrace setregs: %w", err)
	}

	err = t.runToBreakpoint()
	if err != nil {
		return uint64(errorReturn), err
	}

	err = errors.WithStack(unix.PtraceGetRegs(t.Pid, &resultRegs))
	if err != nil {
		return uint64(errorReturn), errors.Errorf("ptrace getregs: %w", err)
	}

	if resultRegs.Rax > maxErrno {
		return uint64(errorReturn), errors.WithStack(unix.Errno(-resultRegs.Rax))
	}

	newPayload, err := t.readData(uintptr(start), len(payload))
	if err != nil {
		return uint64(errorReturn), err
	}
	copy(payload, newPayload)

	return resultRegs.Rax, nil
}

// Syscalls can be interrupted by signal handling and might abort. So we
// wrap them with a loop which retries them automatically if interrupted.
// We do not handle EAGAIN here on purpose, to not block in a loop.
func (t *Tracee) doSyscall(useMemory bool, call int, args func(start uint64) ([]byte, [6]uint64, errors.E)) (uint64, errors.E) {
	// TODO: Handle ERESTART_RESTARTBLOCK as well and call restart_syscall syscall?
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

// Read from the memory of the tracee.
func (t *Tracee) readData(address uintptr, length int) ([]byte, errors.E) {
	data := make([]byte, length)
	n, e := unix.PtracePeekData(t.Pid, address, data)
	if e != nil {
		return nil, errors.Errorf("ptrace peekdata: %w", e)
	}
	if n != length {
		return nil, errors.Errorf("wanted to read %d bytes, but read %d bytes", length, n)
	}
	return data, nil
}

// Read into the memory of the tracee.
func (t *Tracee) writeData(address uintptr, data []byte) errors.E {
	n, e := unix.PtracePokeData(t.Pid, address, data)
	if e != nil {
		return errors.Errorf("ptrace pokedata: %w", e)
	}
	if n != len(data) {
		return errors.Errorf("wanted to write %d bytes, but wrote %d bytes", len(data), n)
	}
	return nil
}

// When we do a syscall we set opcodes to call a syscall and we put afterwards
// a breakpoint (see syscallInstruction). This function executes those opcodes
// and returns once we hit the breakpoint. During execution signal handlers
// of the trustee might run as well before the breakpoint is reached (this is
// why we use ptrace cont with a breakpoint and not ptrace single step).
func (t *Tracee) runToBreakpoint() errors.E {
	err := errors.WithStack(unix.PtraceCont(t.Pid, 0))
	if err != nil {
		return errors.Errorf("run to breakpoint: %w", err)
	}

	// 0 trap cause means a breakpoint or single stepping.
	return t.waitTrap(0)
}

func (t *Tracee) waitTrap(cause int) errors.E {
	for {
		var status unix.WaitStatus
		var e error
		for {
			_, e = unix.Wait4(t.Pid, &status, 0, nil)
			if e == nil || !errors.Is(e, unix.EINTR) {
				break
			}
		}
		if e != nil {
			return errors.Errorf("wait trap: %w", e)
		}
		// A breakpoint or other trap cause we expected has been reached.
		if status.TrapCause() == cause {
			return nil
		} else if status.TrapCause() != -1 {
			t.LogWarnf("unexpected trap cause for PID %d: %d, expected %d", t.Pid, status.TrapCause(), cause)
			return nil
		} else if status.Stopped() {
			// If the tracee stopped it might have stopped for some other signal. While a tracee is
			// ptraced any signal it receives stops the tracee for us to decide what to do about the
			// signal. In our case we just pass the signal back to the tracee using ptrace cont and
			// let its signal handler do its work.
			err := errors.WithStack(unix.PtraceCont(t.Pid, int(status.StopSignal())))
			if err != nil {
				return errors.Errorf("wait trap: ptrace cont with %d: %w", int(status.StopSignal()), err)
			}
			continue
		}
		return errors.Errorf(
			"wait trap: unexpected wait status after wait, exit status %d, signal %d, stop signal %d, trap cause %d, expected trap cause %d",
			status.ExitStatus(), status.Signal(), status.StopSignal(), status.TrapCause(), cause,
		)
	}
}

// Redirects stdout and stderr of the process with PID pid to provided stdoutWriter and stderrWriter.
// Additionally, it copies original stdout and stderr (before redirect) from the process with PID to
// this process and returns them. Make sure to close them once you do not need them anymore.
//
//nolint:nakedret
func RedirectStdoutStderr(debugLog bool, logWarnf func(msg string, args ...any), pid int, stdoutWriter, stderrWriter *os.File) (stdout, stderr *os.File, err errors.E) {
	t := Tracee{
		Pid:      pid,
		DebugLog: debugLog,
		LogWarnf: logWarnf,
	}

	err = t.Attach()
	if err != nil {
		return
	}
	defer func() {
		err2 := t.Detach()
		err = errors.Join(err, err2)
	}()

	fds, err := t.GetFds([]int{1, 2})
	if err != nil {
		// Some file descriptors might be retrieved, so we close them before returning.
		for _, fd := range fds {
			if fd != -1 {
				unix.Close(fd)
			}
		}
		return
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

	err = t.SetFd(int(stdoutWriter.Fd()), 1)
	if err != nil {
		return
	}
	err = t.SetFd(int(stderrWriter.Fd()), 2) //nolint:gomnd
	if err != nil {
		return
	}

	return
}

// ReplaceFdForProcessFds copies traceeFds to this process to see which ones if any match
// "from". If match is found, we replace it with "to" by copying "to" to the tracee and set it
// instead of the corresponding traceeFd.
//
//nolint:nakedret
func ReplaceFdForProcessFds(debugLog bool, logWarnf func(msg string, args ...any), pid int, traceeFds []int, from, to *os.File) (err errors.E) {
	t := Tracee{
		Pid:      pid,
		DebugLog: debugLog,
		LogWarnf: logWarnf,
	}

	err = t.Attach()
	if err != nil {
		return
	}
	defer func() {
		err2 := t.Detach()
		err = errors.Join(err, err2)
	}()

	hostFds, err := t.GetFds(traceeFds)
	// We close retrieved file descriptors no matter what on returning from this function.
	defer func() {
		for _, fd := range hostFds {
			if fd != -1 {
				unix.Close(fd)
			}
		}
	}()
	if err != nil {
		return
	}

	// When there is no error, number of file descriptors in hostFds should be the same
	// as file descriptors in traceeFds, but some might be -1, which we skip. They can
	// be -1 because file descriptors might be closed since the time we enumerated them.
	for i, hostFd := range hostFds {
		if hostFd == -1 {
			continue
		}
		equal, err := equalFds(hostFd, int(from.Fd()))
		if err != nil {
			return err
		}
		if !equal {
			continue
		}

		err = t.SetFd(int(to.Fd()), traceeFds[i])
		if err != nil {
			return err
		}
	}

	return
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
			return errors.Errorf("failed to parse fd %s: %w", entry.Name(), e)
		}
		fds = append(fds, fd)
	}

	return ReplaceFdForProcessFds(debugLog, logWarnf, pid, fds, from, to)
}

func equalFds(fd1, fd2 int) (bool, errors.E) {
	var stat1 unix.Stat_t
	err := errors.WithStack(unix.Fstat(fd1, &stat1))
	if err != nil {
		return false, err
	}
	var stat2 unix.Stat_t
	err = errors.WithStack(unix.Fstat(fd2, &stat2))
	if err != nil {
		return false, err
	}
	return stat1.Dev == stat2.Dev && stat1.Ino == stat2.Ino && stat1.Rdev == stat2.Rdev, nil
}

// A file descriptor we redirected in a direct children process might have been further inherited or
// duplicated. Because of that we copied the original file descriptor to this process (into from) and
// traverse the direct children and its descendants and search and replace for any copy of the file
// descriptor matching from, which we then replace with to. To do the matching we have to copy all file
// descriptors to this process. This is inherently racy as new children processes might be made after we
// have enumerated them. Because we replace file descriptors in the parent process before we go to its
// children we hope that any new children which are made while this function runs use replaced file descriptors.
func replaceFdForProcessAndChildren(debugLog bool, logWarnf func(msg string, args ...any), pid int, name string, from, to *os.File) errors.E {
	eq, err := equalFds(int(from.Fd()), int(to.Fd()))
	if err != nil {
		return errors.Errorf("unable to compare file descriptors: %w", err)
	}
	if eq {
		// Nothing to replace.
		return nil
	}

	err = replaceFdForProcess(debugLog, logWarnf, pid, from, to)
	if err != nil {
		if debugLog {
			logWarnf("error replacing %s fd for process with PID %d: %+v", name, pid, err)
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
		return errors.Errorf("unable to read process tasks from %s: %w", taskPath, e)
	}

	for _, entry := range entries {
		childrenPath := fmt.Sprintf("/proc/%d/task/%s/children", pid, entry.Name())
		childrenData, e := os.ReadFile(childrenPath)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			return errors.Errorf("unable to read process children from %s: %w", childrenPath, e)
		}
		childrenPids := strings.Fields(string(childrenData))
		for _, childPid := range childrenPids {
			p, e := strconv.Atoi(childPid)
			if e != nil {
				return errors.Errorf("failed to parse PID %s: %w", childPid, e)
			}
			err := replaceFdForProcessAndChildren(debugLog, logWarnf, p, name, from, to)
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
//
//nolint:nakedret
func RedirectAllStdoutStderr(debugLog bool, logWarnf func(msg string, args ...any), pid int) (stdout, stderr *os.File, err errors.E) {
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
		return
	}
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
	defer stdoutWriter.Close()
	stderr, stderrWriter, e := os.Pipe()
	if e != nil {
		err = errors.WithStack(e)
		return
	}
	// Writer is not needed once it is (successfully or not) passed to the adopted process.
	defer stderrWriter.Close()

	originalStdout, originalStderr, err := RedirectStdoutStderr(debugLog, logWarnf, pid, stdoutWriter, stderrWriter)
	if err != nil {
		return
	}
	if originalStdout != nil {
		defer originalStdout.Close()
	}
	if originalStderr != nil {
		defer originalStderr.Close()
	}

	if originalStdout != nil {
		err = replaceFdForProcessAndChildren(debugLog, logWarnf, pid, "stdout", originalStdout, stdoutWriter)
		if err != nil {
			return
		}
	}

	if originalStderr != nil {
		err = replaceFdForProcessAndChildren(debugLog, logWarnf, pid, "stderr", originalStderr, stderrWriter)
		if err != nil {
			return
		}
	}

	return
}
