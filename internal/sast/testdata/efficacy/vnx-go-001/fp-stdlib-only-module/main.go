// A standard-library-only module has no dependencies to checksum, so the go
// command never writes a go.sum for it.
package main

import "net/http"

func main() {
	http.Handle("/", http.FileServer(http.Dir("./public")))
	_ = http.ListenAndServe(":8080", nil)
}
