package server

import (
	"log"
	"net/http"
	"net/http/httputil"
)

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
~>		log.Printf("request %s headers=%v", r.URL.Path, r.Header)
		dump, _ := httputil.DumpRequest(r, true)
~>		log.Println(string(dump))
		r.ParseForm()
~>		logger.Infof("form: %+v", r.PostForm)
		next.ServeHTTP(w, r)
	})
}
