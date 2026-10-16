package proto

import "strconv"

func parse(fields []string) (*Frame, error) {
	seq, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return nil, err
	}
	f := &Frame{}
~>	f.Seq = int16(seq)
	return f, nil
}
