package auth

import (
	"fmt"
	"log"
)

func Exchange(code string) (string, error) {
	tok, err := fetch(code)
	if err != nil {
		return "", err
	}
~>	log.Printf("got access token %s", tok.AccessToken)
~>	fmt.Println("client secret:", cfg.ClientSecret)
	return tok.AccessToken, nil
}
