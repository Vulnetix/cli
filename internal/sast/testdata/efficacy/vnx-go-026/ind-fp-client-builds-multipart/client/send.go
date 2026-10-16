package client

import (
	"bytes"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
)

func Body(path string) (*bytes.Buffer, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	part, err := mw.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, "", err
	}
	io.Copy(part, f)
	mw.Close()
	return buf, mw.FormDataContentType(), nil
}
