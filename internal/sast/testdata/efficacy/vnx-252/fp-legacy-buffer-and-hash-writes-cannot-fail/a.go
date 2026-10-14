package a

func f(b []byte) {
	var buf bytes.Buffer
	buf.Write(b)
	h := sha256.New()
	h.Write(b)
}
