package server

import (
	"fmt"
	"net/http"
	"runtime/debug"
)

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				w.WriteHeader(http.StatusInternalServerError)
~>				fmt.Fprintf(w, "panic: %v\n%s", rec, debug.Stack())
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func Fail(w http.ResponseWriter, err error) {
~>	http.Error(w, err.Error()+"\n"+string(debug.Stack()), http.StatusInternalServerError)
}

func Dump(w http.ResponseWriter) {
	stack := debug.Stack()
~>	w.Write(stack)
}
