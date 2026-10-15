package api

import "net/http"

func whoami(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	w.Write([]byte(c.Value))
}

func callUpstream(sid string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://upstream.internal/me", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sid})
	req.Header.Set("Cookie", "theme=dark")
	return http.DefaultClient.Do(req)
}

func secureHeader(w http.ResponseWriter, id string) {
	w.Header().Add("Set-Cookie", "session="+id+"; Path=/; Secure; HttpOnly")
}
