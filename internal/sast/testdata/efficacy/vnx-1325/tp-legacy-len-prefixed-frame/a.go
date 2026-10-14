package a

func f(b []byte) []byte {
	size := binary.BigEndian.Uint32(b)
~>	body := make([]byte, size)
	return body
}
