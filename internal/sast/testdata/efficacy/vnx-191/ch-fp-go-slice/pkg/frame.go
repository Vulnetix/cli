package frame

func Body(b []byte, n int) []byte {
	return b[4 : len(b)-4]
}
