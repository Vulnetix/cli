package store

func (s *Store) flush(f *os.File, out io.Writer, src io.Reader) error {
	if _, err := f.WriteString(s.header); err != nil {
		return err
	}
	n, err := io.Copy(out, src)
	_ = os.WriteFile(s.path, s.data, 0o600)
	defer f.Sync()
	return f.Sync()
}

func (s *Store) Write(p []byte) (int, error) {
	return s.w.Write(p)
}

func digest(data string, alg string) []byte {
	h := newHash(alg)()
	h.Write([]byte(data))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return append(h.Sum(nil), mac.Sum(nil)...)
}
