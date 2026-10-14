package client

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

func logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "remember", Value: "", Expires: time.Unix(0, 0)})
}

func call(req *http.Request, jar *cookiejar.Jar, u *url.URL, sid string) {
	req.AddCookie(&http.Cookie{Name: "session", Value: sid})
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: sid}})
}
