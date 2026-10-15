package flags

func Blocking(flags, mask uint32) bool {
	return flags&mask == 0
}

func Be16(hi, lo uint16) uint16 {
	return hi<<8 + lo
}
