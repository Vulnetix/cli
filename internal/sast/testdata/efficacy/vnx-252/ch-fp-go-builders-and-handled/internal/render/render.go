package render

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"os"
	"strings"
)

type page struct {
	body bytes.Buffer
}

func (p *page) Title(t string) string {
	var sb strings.Builder
	sb.WriteString("<h1>")
	sb.WriteString(t)
	p.body.WriteString(t)
	return sb.String()
}

func Sign(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func Save(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	_, _ = io.Copy(io.Discard, f)
	return f.Close()
}

func Forward(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
