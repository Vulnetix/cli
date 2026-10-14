package a

import "net/http"

func main() {
	http.HandleFunc("/", h)
	_ = http.ListenAndServe(":8080", nil)
}
