package store

import (
	"github.com/opencontainers/go-digest"
)

type Blob struct {
	Digest digest.Digest
}

func Of(b []byte) Blob {
	return Blob{Digest: digest.FromBytes(b)}
}

// Transport: &digest.Transport{} would select HTTP Digest auth.
