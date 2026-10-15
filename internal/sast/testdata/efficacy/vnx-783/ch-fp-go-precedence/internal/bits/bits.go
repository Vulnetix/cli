package bits

func Pack(x, y uint32, flags, mask uint32) (uint32, bool) {
	v := x<<8 + y
	if flags&mask == 0 {
		return v, false
	}
	return v, true
}
