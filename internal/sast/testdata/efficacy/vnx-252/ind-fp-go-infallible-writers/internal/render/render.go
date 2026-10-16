package render

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"os"
	"strings"
)

func Sign(key, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil)
}

func Join(parts []string) string {
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(p)
		sb.WriteString(",")
	}
	return sb.String()
}

func Buffer(parts [][]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(p)
	}
	return buf.Bytes()
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

func Lines(lines []string) error {
	bw := bufio.NewWriter(os.Stdout)
	for _, l := range lines {
		bw.WriteString(l)
	}
	return bw.Flush()
}
