//go:build linux && (amd64 || arm64)

// Package execguard runs a workload under the sensor and decides about every
// program it starts, before the program runs.
//
// It is for where there is no eBPF: Fargate, gVisor-less containers that may
// not load BPF, any host where the sensor cannot run privileged. The sensor
// becomes the workload's entrypoint (vulnetix-sensor run -- <command>), puts
// a seccomp filter on the workload that sends every execve and execveat to
// the sensor through a user notification, and answers each one: continue, or
// refuse with EPERM. Every other system call runs at full speed; only program
// starts stop.
//
// Refusing an exec is reversible (the next attempt can be allowed), so guard
// mode may hold one, unlike stopping a running process.
//
// Two limits, stated plainly:
//
//   - The path is read from the workload's memory while it waits. A workload
//     with a second thread can change that memory between the check and the
//     kernel's own read. This is a policy control for software that is not
//     already hostile, not a sandbox against code that is.
//   - It needs no privilege beyond NO_NEW_PRIVS, which also means a setuid
//     binary in the workload no longer gains privileges when it runs.
package execguard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ChildEnv marks the re-executed sensor that installs the filter and then
// becomes the workload.
const ChildEnv = "__VULNETIX_EXECGUARD_CHILD"

// Exec is one program start the workload asked for.
type Exec struct {
	PID  int
	Path string // absolute, resolved against the caller's working directory
	Argv []string
}

// Decider answers an exec: nil to allow, an error to refuse with EPERM.
type Decider func(Exec) error

// MaybeChild runs the child half when this process is the re-executed sensor.
// Call it first thing in main; it does not return in the child.
func MaybeChild() {
	fdText := os.Getenv(ChildEnv)
	if fdText == "" {
		return
	}
	if err := child(fdText); err != nil {
		fmt.Fprintln(os.Stderr, "vulnetix-sensor: exec guard:", err)
		os.Exit(126)
	}
}

func syscallNumbers() (arch uint32, execve, execveat uint32) {
	if runtime.GOARCH == "arm64" {
		return unix.AUDIT_ARCH_AARCH64, 221, 281
	}

	return unix.AUDIT_ARCH_X86_64, 59, 322
}

// filter sends execve and execveat to the supervisor and allows everything
// else. A system call made through another architecture's ABI (x32, i386 on
// amd64) is refused rather than slipping past.
func filter() []unix.SockFilter {
	arch, execve, execveat := syscallNumbers()
	const (
		ld  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		ret = unix.BPF_RET | unix.BPF_K
	)

	return []unix.SockFilter{
		{Code: ld, K: 4},                   // seccomp_data.arch
		{Code: jeq, Jt: 1, Jf: 0, K: arch}, // our ABI: go on
		{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: ld, K: 0}, // seccomp_data.nr
		{Code: jeq, Jt: 2, Jf: 0, K: execve},
		{Code: jeq, Jt: 1, Jf: 0, K: execveat},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ret, K: unix.SECCOMP_RET_USER_NOTIF},
	}
}

// child installs the filter on its own thread, hands the listener to the
// supervisor, and execs the workload from that same thread so the new image
// inherits the filter.
func child(fdText string) error {
	sockFD, err := strconv.Atoi(fdText)
	if err != nil {
		return fmt.Errorf("bad %s", ChildEnv)
	}
	args := os.Args
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i

			break
		}
	}
	if sep < 0 || sep+1 >= len(args) {
		return errors.New("no command after --")
	}
	argv := args[sep+1:]
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	prog := filter()
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	listener, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	if err := unix.Sendmsg(sockFD, []byte{0}, unix.UnixRights(int(listener)), nil, 0); err != nil {
		return fmt.Errorf("hand over listener: %w", err)
	}
	_ = unix.Close(int(listener))
	_ = unix.Close(sockFD)

	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, ChildEnv+"=") {
			env = append(env, kv)
		}
	}

	// This exec is the first notification the supervisor sees, and it allows
	// it: it is the command the operator asked to run.
	return unix.Exec(path, argv, env)
}

// Run starts command under the guard and returns its exit code.
func Run(command []string, decide Decider) (int, error) {
	if len(command) == 0 {
		return 0, errors.New("no command to run")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	parentEnd := os.NewFile(uintptr(pair[0]), "execguard-parent")
	childEnd := os.NewFile(uintptr(pair[1]), "execguard-child")
	defer parentEnd.Close()

	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(self, append([]string{"--"}, command...)...)
	cmd.Args[0] = command[0]
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childEnd} // fd 3 in the child
	cmd.Env = append(os.Environ(), ChildEnv+"=3")
	if err := cmd.Start(); err != nil {
		childEnd.Close()

		return 0, err
	}
	childEnd.Close()

	listener, err := receiveFD(int(parentEnd.Fd()))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return 0, fmt.Errorf("the workload did not hand over its seccomp listener: %w", err)
	}

	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	go func() {
		for s := range signals {
			_ = cmd.Process.Signal(s)
		}
	}()

	go serve(listener, decide, cmd.Process.Pid)

	err = cmd.Wait()
	_ = unix.Close(listener)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}

		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}

	return 0, nil
}

func receiveFD(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return -1, errors.New("no control message")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return -1, errors.New("no descriptor")
	}

	return fds[0], nil
}

type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  struct {
		Nr   int32
		Arch uint32
		IP   uint64
		Args [6]uint64
	}
}

type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// serve answers notifications until the listener closes. The first exec is
// the workload itself and is allowed without asking.
func serve(listener int, decide Decider, rootPID int) {
	_, execve, _ := syscallNumbers()
	first := true
	for {
		var n seccompNotif
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(&n))); errno != 0 {
			if errno == unix.EINTR || errno == unix.ENOENT {
				continue
			}

			return
		}
		resp := seccompNotifResp{ID: n.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
		if first && int(n.PID) == rootPID {
			first = false
		} else {
			pathArg, argvArg := n.Data.Args[0], n.Data.Args[1]
			dirfd := int64(unix.AT_FDCWD)
			if uint32(n.Data.Nr) != execve {
				dirfd, pathArg, argvArg = int64(int32(n.Data.Args[0])), n.Data.Args[1], n.Data.Args[2]
			}
			e, err := readExec(int(n.PID), dirfd, pathArg, argvArg)
			// The notification may have been cancelled while we read: the
			// process died, or a signal interrupted the call.
			if !idValid(listener, n.ID) {
				continue
			}
			if err == nil && decide != nil {
				if refusal := decide(e); refusal != nil {
					resp = seccompNotifResp{ID: n.ID, Error: -int32(unix.EPERM)}
				}
			}
		}
		_, _, _ = unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&resp)))
	}
}

func idValid(listener int, id uint64) bool {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener), unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id)))

	return errno == 0
}

// readExec reads the path and up to 64 arguments from the waiting process.
func readExec(pid int, dirfd int64, pathPtr, argvPtr uint64) (Exec, error) {
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return Exec{}, err
	}
	defer mem.Close()
	path, err := readString(mem, pathPtr)
	if err != nil {
		return Exec{}, err
	}
	if !filepath.IsAbs(path) {
		base := fmt.Sprintf("/proc/%d/cwd", pid)
		if dirfd != int64(unix.AT_FDCWD) {
			base = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
		}
		if dir, err := os.Readlink(base); err == nil {
			path = filepath.Join(dir, path)
		}
	}
	e := Exec{PID: pid, Path: filepath.Clean(path)}
	for i := 0; i < 64 && argvPtr != 0; i++ {
		var ptr [8]byte
		if _, err := mem.ReadAt(ptr[:], int64(argvPtr)+int64(i*8)); err != nil {
			break
		}
		p := *(*uint64)(unsafe.Pointer(&ptr[0]))
		if p == 0 {
			break
		}
		s, err := readString(mem, p)
		if err != nil {
			break
		}
		e.Argv = append(e.Argv, s)
	}

	return e, nil
}

func readString(mem *os.File, addr uint64) (string, error) {
	var out []byte
	buf := make([]byte, 256)
	for len(out) < 4096 {
		n, err := mem.ReadAt(buf, int64(addr)+int64(len(out)))
		if n > 0 {
			if i := indexZero(buf[:n]); i >= 0 {
				return string(append(out, buf[:i]...)), nil
			}
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if len(out) > 0 {
				return string(out), nil
			}

			return "", err
		}
	}

	return string(out), nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}

	return -1
}
