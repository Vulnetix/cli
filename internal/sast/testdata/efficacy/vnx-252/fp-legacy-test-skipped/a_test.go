package a

func f(conn net.Conn, b []byte) {
	conn.Write(b)
}
