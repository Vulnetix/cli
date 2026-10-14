package auth

import (
	"log"
	"os"
)

func Login(user, password string) error {
~>	log.Printf("login attempt user=%s password=%s", user, password)
	accessToken, err := issue(user)
	if err != nil {
		return err
	}
~>	log.Println("issued token:", accessToken)
	return nil
}

func load(req *LoginRequest) {
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
~>	log.Printf("oauth configured with %q", clientSecret)
~>	log.Fatalf("cannot authenticate %s with %s", req.Username, req.Password)
}
