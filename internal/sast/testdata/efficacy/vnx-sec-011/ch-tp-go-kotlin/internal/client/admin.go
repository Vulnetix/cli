package client

import "net/http"

const adminToken = `
~>@@sample:e[y]JhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9[.]eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMH0[.]wmUk[-]yHz4N9sDuOIR0NX3[-]Z45NYAkrwWWxpO8Tq8AXU@@`

func authorise(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+adminToken)
}
