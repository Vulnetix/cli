package lsmguard

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestKeyAndRecordMatchTheCLayout(t *testing.T) {
	if unsafe.Sizeof(fileKey{}) != 16 {
		t.Fatalf("fileKey is %d bytes; struct file_key is 16", unsafe.Sizeof(fileKey{}))
	}
	b := make([]byte, refusalSize)
	le := binary.LittleEndian
	le.PutUint64(b[0:], 0x1234)
	le.PutUint32(b[8:], 0x0800001)
	le.PutUint32(b[12:], 3)
	le.PutUint32(b[16:], 4242)
	le.PutUint32(b[20:], 1)
	r, err := decodeRefusal(b)
	if err != nil || r.key.Ino != 0x1234 || r.key.Dev != 0x0800001 || r.rule != 3 || r.pid != 4242 || !r.enforced {
		t.Fatalf("decoded %+v, %v", r, err)
	}
	if _, err := decodeRefusal(b[:10]); err == nil {
		t.Fatal("a short record should be refused")
	}
}

func TestKernelDevKeepsTheMinorInTwentyBits(t *testing.T) {
	// /dev/nvme0n1p2 is 259:2; the kernel's dev_t is (259 << 20) | 2.
	if got := kernelDev(259, 2); got != 259<<20|2 {
		t.Fatalf("kernelDev(259, 2) = %#x", got)
	}
}
