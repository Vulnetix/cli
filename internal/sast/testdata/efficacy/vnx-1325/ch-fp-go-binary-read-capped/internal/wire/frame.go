package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

const maxFrame = 1 << 20

func ReadFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > maxFrame {
		return nil, errors.New("frame too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
