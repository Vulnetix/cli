package proto

import (
	"io"
	"net"
	"os"
)

func Send(conn net.Conn, b []byte) error {
	if _, err := conn.Write(b); err != nil {
		return err
	}
	_, _ = conn.Write([]byte("\n"))
	return nil
}

func Save(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func Pipe(dst io.Writer, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, src)
	return n, err
}

func Close(f *os.File) {
	defer f.Close()
	_ = f.Sync()
}
