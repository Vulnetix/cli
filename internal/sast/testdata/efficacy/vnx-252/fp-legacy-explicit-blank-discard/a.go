package a

func f(c io.Closer, w io.Writer, b []byte) {
	_ = c.Close()
	_, _ = w.Write(b)
}
