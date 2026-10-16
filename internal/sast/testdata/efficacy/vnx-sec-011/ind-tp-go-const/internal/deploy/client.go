package deploy

import "net/http"

~>const deployToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2JpbGUtc3luYyIsInRlbmFudCI6ImFjbWUiLCJleHAiOjQxMDI0NDQ4MDB9.xKjzuxlWS1KU6cE3qbfrPvUeZfAz5u_uKvcrJKXdVIk"

func Authorize(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+deployToken)
}
