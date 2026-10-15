package auth

import "testing"

func TestLogin(t *testing.T) {
	password := "correct horse battery staple"
	tok, err := login("alice", password)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got token %s for password %s", tok, password)
}
