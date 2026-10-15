package proxy

import "net/http"

// HeaderXFF names the header this proxy appends to.
const HeaderXFF = "X-Forwarded-For"

func forward(out *http.Request, in *http.Request) {
	host := in.RemoteAddr
	out.Header.Set("X-Forwarded-For", host)
}
