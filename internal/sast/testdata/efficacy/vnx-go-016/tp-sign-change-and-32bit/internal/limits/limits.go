package limits

import "strconv"

type Limits struct {
	MaxConns uint
	Weight   int32
	Shard    int16
}

func Parse(conns, weight, shard string) (Limits, error) {
	var l Limits
	if c, err := strconv.Atoi(conns); err == nil {
~>		l.MaxConns = uint(c)
	}
	w, err := strconv.ParseUint(weight, 10, 32)
	if err != nil {
		return l, err
	}
~>	l.Weight = int32(w)
	s, err := strconv.ParseInt(shard,
		10, 32)
	if err != nil {
		return l, err
	}
~>	l.Shard = int16(s)
	return l, nil
}
