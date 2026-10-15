package auth

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var Config = &oauth2.Config{
	ClientID:     "@@sample:1[2]34[5]67[8]90[1]2[-][a]bc[d]ef[g]hi[j]kl[m]no[p]qr[s]tu[v]wx[y]z0[1]23[4]5@@.apps.googleusercontent.com",
~>	ClientSecret: "GOCSPX-@@sample:[A-Za-z0-9_-]{28}@@",
	Endpoint:     google.Endpoint,
}
