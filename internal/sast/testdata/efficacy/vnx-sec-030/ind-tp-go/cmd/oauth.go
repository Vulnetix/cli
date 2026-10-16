package main

import "golang.org/x/oauth2"

var conf = &oauth2.Config{
	ClientID: "1234-abc.apps.googleusercontent.com",
~>	ClientSecret: "GOCSPX-@@sample:[A-Za-z0-9_-]{28}@@",
}
