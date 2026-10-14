package unfurl

import (
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"
)

var errBlocked = errors.New("destination not allowed")

// Every connection the client makes is checked after DNS resolution, so a
// caller-chosen URL cannot reach loopback, link-local or private addresses.
var safeClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{Control: denyInternal}).DialContext,
	},
}

func denyInternal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return errBlocked
	}
	return nil
}

func Unfurl(w http.ResponseWriter, r *http.Request) {
	resp, err := safeClient.Get(r.FormValue("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp.Body.Close()
}
