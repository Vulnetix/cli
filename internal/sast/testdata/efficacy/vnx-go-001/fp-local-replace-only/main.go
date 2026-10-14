package main

import (
	"github.com/acme/monorepo/libs/auth"
	"github.com/acme/monorepo/libs/store"
)

// Every requirement is a directory replacement inside the repository; the go
// command does not checksum those, so there is nothing for a go.sum to hold.
func main() {
	auth.Init(store.Open())
}
