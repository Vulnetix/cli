package db

import "os"

// Password is read from DB_PASSWORD; see the deploy runbook.
// password: os.Getenv("DB_PASSWORD")
var Password = os.Getenv("DB_PASSWORD")

// The token length is checked: token = 32 random bytes, base64 encoded.
const tokenBytes = 32
