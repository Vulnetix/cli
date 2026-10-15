package h

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
)

func Sum(r io.Reader) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("prefix")
	var sb strings.Builder
	sb.WriteString("x")
	h := sha256.New()
	h.Write([]byte(sb.String()))
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
