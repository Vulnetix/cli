package wire

import (
	"encoding/binary"
	"io"
)

func ReadFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
~>	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}
