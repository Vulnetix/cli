package auth

import "os"

var secret = os.Getenv("GOOGLE_CLIENT_SECRET")
const prefix = "GOCSPX-"
