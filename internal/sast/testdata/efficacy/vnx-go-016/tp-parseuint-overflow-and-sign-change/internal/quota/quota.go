package quota

import "strconv"

// A uint64 above MaxInt64 turns negative; a negative signed value turns into
// an enormous unsigned one.
func Parse(maxBytes, offset, level string) (int64, uint64, int16, error) {
	mb, err := strconv.ParseUint(maxBytes, 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
~>	limit := int64(mb)

	off, err := strconv.ParseInt(offset, 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
~>	start := uint64(off)

	lv, err := strconv.ParseUint(level, 10, 16)
	if err != nil {
		return 0, 0, 0, err
	}
~>	return limit, start, int16(lv), nil
}
