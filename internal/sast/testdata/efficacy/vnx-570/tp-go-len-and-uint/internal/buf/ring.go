package buf

import "errors"

var ErrShort = errors.New("short buffer")

func Take(p []byte, n uint) ([]byte, error) {
~>	if len(p) < 0 {
		return nil, ErrShort
	}
~>	if n < 0 {
		return nil, ErrShort
	}
	return p[:n], nil
}

func Window(p []byte, off int) []byte {
	start := uint(off)
~>	if start < 0 || len(p[start:]) == 0 {
		return nil
	}
	return p[start:]
}
