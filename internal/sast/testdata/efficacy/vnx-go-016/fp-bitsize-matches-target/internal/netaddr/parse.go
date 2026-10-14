package netaddr

import "strconv"

// ParseInt/ParseUint with a bit size no wider than the target already reject
// out-of-range input, so the conversion cannot truncate.
func Parse(port, octet, ttl, delta, win string) (uint16, uint8, int32, int8, uint) {
	p, _ := strconv.ParseUint(port, 10, 16)
	o, _ := strconv.ParseUint(octet, 10, 8)
	t, _ := strconv.ParseInt(ttl, 10, 32)
	d, _ := strconv.ParseInt(delta, 10, 8)
	w, _ := strconv.ParseUint(win, 10, 32)
	small, _ := strconv.ParseUint(octet, 10, 8)
	return uint16(p), uint8(o), int32(t), int8(d), uint(w) + uint(int16(small))
}
