// Package lsmguard refuses execs in the kernel with a BPF LSM program on
// bprm_check_security, for hosts whose kernel runs the bpf LSM (lsm=...,bpf)
// and where the sensor runs with CAP_BPF and CAP_SYS_ADMIN.
//
// The program matches a file by identity (inode and device), not by path, so
// a renamed or hard-linked copy of a blocked binary is refused too. The
// sensor fills its map from the exact program paths its block-mode rules
// name, resolved on the host filesystem. Off unless --bpf-lsm is set.
//
// Limits, stated plainly: the identity of a file on an overlay filesystem or
// a btrfs subvolume can differ between stat and the kernel's view, so a path
// there may not match; a replaced file is a new inode and is only covered
// after the next sync. Not yet run on a live kernel: the object is verified
// to load as a spec, not by the kernel's verifier.
package lsmguard

import (
	"encoding/binary"
	"errors"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
)

//go:generate clang -O2 -g -target bpfel -c bpf/exec_guard.c -o bpf/exec_guard.o
//go:generate llvm-strip -g bpf/exec_guard.o

// Entry is one program path to refuse and the rule that names it.
type Entry struct {
	Path string
	Rule decide.RuleRef
}

// Refusal is one exec the program matched.
type Refusal struct {
	Path     string
	Rule     decide.RuleRef
	PID      int
	Enforced bool
}

// fileKey matches struct file_key in bpf/exec_guard.c.
type fileKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// refusalSize is sizeof(struct refusal) in bpf/exec_guard.c.
const refusalSize = 24

type rawRefusal struct {
	key      fileKey
	rule     uint32
	pid      uint32
	enforced bool
}

func decodeRefusal(b []byte) (rawRefusal, error) {
	if len(b) < refusalSize {
		return rawRefusal{}, errors.New("short refusal record")
	}
	le := binary.LittleEndian

	return rawRefusal{
		key:      fileKey{Ino: le.Uint64(b[0:8]), Dev: le.Uint32(b[8:12])},
		rule:     le.Uint32(b[12:16]),
		pid:      le.Uint32(b[16:20]),
		enforced: le.Uint32(b[20:24]) != 0,
	}, nil
}

// kernelDev turns a userspace device number (stat's st_dev) into the
// kernel's dev_t, which keeps the minor in the low 20 bits.
func kernelDev(major, minor uint32) uint32 { return major<<20 | minor&0xfffff }
