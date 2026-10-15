package mac

// ValidMAC compares the expected and supplied HMAC tags.
func ValidMAC(expected, supplied []byte) bool {
	if len(expected) != len(supplied) {
		return false
	}
	for i := range expected {
~>		if expected[i] != supplied[i] {
			return false
		}
	}
	return true
}
