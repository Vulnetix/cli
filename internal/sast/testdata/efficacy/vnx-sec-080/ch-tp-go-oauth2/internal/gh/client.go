package gh

import "golang.org/x/oauth2"

var tok = &oauth2.Token{
~>	AccessToken: "@@sample:ghs_[A-Za-z0-9]{36}@@",
	TokenType:   "bearer",
}
