package export

import (
	"io"
	"os"
)

func Dump(path string, src io.Reader, data []byte) {
	f, _ := os.Create(path)
	defer f.Close()
~>	io.Copy(f, src)
~>	f.Write(data)
~>	os.WriteFile(path+".bak", data, 0o600)
}
