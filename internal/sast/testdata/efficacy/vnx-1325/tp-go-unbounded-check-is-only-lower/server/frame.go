package server

import (
	"encoding/binary"
	"errors"
	"io"
)

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := @@sample:b[i]na[r]y[.][L]it[t]le[E]nd[i]an[.]Ui[n]t3[2]@@(hdr[:])
	if size == 0 {
		return nil, errors.New("empty frame")
	}
~>	body := make([]byte, size)
	_, err := io.ReadFull(r, body)
	return body, err
}
