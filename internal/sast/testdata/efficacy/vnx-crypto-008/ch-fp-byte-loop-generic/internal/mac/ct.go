package mac

// ValidMAC compares the HMAC tags in constant time.
func ValidMAC(expected, supplied []byte) bool {
	if len(expected) != len(supplied) {
		return false
	}
	var v byte
	for i := range expected {
		v |= expected[i] ^ supplied[i]
	}
	return v == 0
}
