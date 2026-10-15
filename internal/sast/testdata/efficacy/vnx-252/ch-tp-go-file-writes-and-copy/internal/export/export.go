package export

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

func Save(path string, data []byte) {
	out, err := os.Create(path)
	if err != nil {
		return
	}
	defer out.Close()
~>	out.Write(data)
}

func Mirror(dst *os.File, resp *http.Response) {
~>	io.Copy(dst, resp.Body)
}

func Dump(path string, b []byte) {
~>	os.WriteFile(path, b, 0o600)
~>	ioutil.WriteFile(path+".bak", b, 0o600)
}

func (s *Session) Send(msg []byte) {
~>	s.conn.Write(msg)
}
