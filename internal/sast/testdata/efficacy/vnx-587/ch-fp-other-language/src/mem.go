package mem

import "unsafe"

var p = (*uint32)(unsafe.Pointer(uintptr(0x40020014)))
