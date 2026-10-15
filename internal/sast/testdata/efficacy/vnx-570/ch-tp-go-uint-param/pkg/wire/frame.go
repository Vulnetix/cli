package wire

import "errors"

var errShort = errors.New("short frame")

func Slice(b []byte, off uint32, n int) ([]byte, error) {
~>	if off < 0 {
		return nil, errShort
	}
~>	if 0 > len(b) {
		return nil, errShort
	}
	return b[off : int(off)+n], nil
}
