package wire

import "strconv"

// Avoid int32(n) after strconv.Atoi(s) without a range check.
func LowByte(s string) byte {
	n, _ := strconv.Atoi(s)
	return byte(n & 0xff)
}

func Clamp(s string) int16 {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	n = max(-32768, min(n, 32767))
	return int16(n)
}

const doc = "strconv.Atoi then uint16(n) truncates"
