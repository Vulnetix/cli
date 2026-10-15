package store

import (
	"io"
	"os"
)

func (s *Store) flush(f *os.File, out io.Writer, src io.Reader) {
~>	f.WriteString(s.header)
~>	io.Copy(out, src)
~>	os.WriteFile(s.path, s.data, 0o600)
~>	s.conn.Write(s.frame)
}
