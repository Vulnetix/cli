package api

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Server struct {
	keys jwk.Set
	pub  any
}

func (s *Server) subject(r *http.Request) (string, error) {
~>	tok, err := jwt.ParseRequest(r, jwt.WithKeySet(s.keys), jwt.WithValidate(true), jwt.WithIssuer("https://login.example.com"))
	if err != nil {
		return "", err
	}
	return tok.Subject(), nil
}

func (s *Server) parseRaw(b []byte) (jwt.Token, error) {
~>	return jwt.Parse(b, jwt.WithKey(jwa.RS256, s.pub))
}
