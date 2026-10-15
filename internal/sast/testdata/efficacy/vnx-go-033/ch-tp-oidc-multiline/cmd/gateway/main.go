package main

import (
	"context"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
)

func main() {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")
	if err != nil {
		log.Fatal(err)
	}
	verifier := provider.Verifier(&oidc.Config{
		SkipExpiryCheck:   false,
~>		SkipClientIDCheck: true,
	})
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		if _, err := verifier.Verify(r.Context(), r.Header.Get("X-Id-Token")); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
