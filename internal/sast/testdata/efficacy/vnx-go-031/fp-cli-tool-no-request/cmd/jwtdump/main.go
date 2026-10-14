package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// jwtdump prints a token's header and claims; it decides nothing.
func main() {
	token, _, err := jwt.NewParser().ParseUnverified(os.Args[1], jwt.MapClaims{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(token.Claims, "", "  ")
	fmt.Println(string(out))
}
