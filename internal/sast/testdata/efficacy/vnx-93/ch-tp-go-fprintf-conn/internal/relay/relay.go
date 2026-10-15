package relay

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

func Forward(w http.ResponseWriter, r *http.Request) {
	conn, err := net.Dial("tcp", "mx.internal:25")
	if err != nil {
		http.Error(w, "relay down", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	rd := bufio.NewReader(conn)
	_, _ = rd.ReadString('\n')
	sender := r.URL.Query().Get("from")
~>	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", sender)
~>	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n",
		r.FormValue("rcpt"))
	fmt.Fprintf(w, "queued for %s\n", sender)
}
