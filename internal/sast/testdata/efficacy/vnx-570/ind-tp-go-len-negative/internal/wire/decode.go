package wire

import (
	"encoding/binary"
	"errors"
)

var errShort = errors.New("wire: short buffer")

func DecodeHeader(p []byte) (uint32, error) {
~>	if len(p) < 0 {
		return 0, errShort
	}
	return binary.BigEndian.Uint32(p[:4]), nil
}
