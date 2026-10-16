package proto

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
)

func SendFrame(conn net.Conn, payload []byte) {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
~>	conn.Write(hdr)
~>	conn.Write(payload)
}

func Mirror(dst io.Writer, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
~>	io.Copy(dst, resp.Body)
	return nil
}

func ReadHeader(r io.Reader) [4]byte {
	var buf [4]byte
~>	io.ReadFull(r, buf[:])
	return buf
}
