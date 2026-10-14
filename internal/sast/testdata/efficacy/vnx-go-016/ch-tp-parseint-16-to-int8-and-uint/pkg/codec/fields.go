package codec

import "strconv"

type Header struct {
	Level int8
	Size  uint
}

func Parse(level, size string) (Header, error) {
	l, err := strconv.ParseInt(level, 10, 16)
	if err != nil {
		return Header{}, err
	}
	n, err := strconv.Atoi(size)
	if err != nil {
		return Header{}, err
	}
	return Header{
~>		Level: int8(l),
~>		Size:  uint(n),
	}, nil
}
