package proto

import "strconv"

type Frame struct {
	Seq   int16
	Flags int8
	Code  rune
}

func Decode(fields []string) (Frame, error) {
	seq, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Frame{}, err
	}
	var f Frame
~>	f.Seq = int16(seq)
	flags, err := strconv.ParseInt(fields[1], 0, 0)
	if err != nil {
		return Frame{}, err
	}
~>	f.Flags = int8(flags)
	code, _ := strconv.ParseInt(fields[2], 16, 64)
~>	f.Code = rune(code)
	return f, nil
}
