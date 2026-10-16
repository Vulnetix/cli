package web

import "net/http"

func call(url, sid string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sid})
	return http.DefaultClient.Do(req)
}

// Example: http.SetCookie(w, &http.Cookie{Name: "a", Value: "b"}) is documented elsewhere.
