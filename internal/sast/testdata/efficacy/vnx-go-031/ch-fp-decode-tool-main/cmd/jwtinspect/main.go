package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// jwtinspect prints a token's header and claims without checking the
// signature, for debugging.
func main() {
	tok, _, err := jwt.NewParser().ParseUnverified(os.Args[1], jwt.MapClaims{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(tok.Claims, "", "  ")
	fmt.Println(string(out))
}
