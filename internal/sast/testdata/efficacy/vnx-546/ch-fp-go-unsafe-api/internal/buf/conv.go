package buf

import "unsafe"

// TODO: switch to unsafe.String once the minimum Go version is 1.20.
func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
