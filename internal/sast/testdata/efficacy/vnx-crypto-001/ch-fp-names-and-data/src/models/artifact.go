package models

import "crypto/sha256"

type Artifact struct {
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

func (a *Artifact) md5Missing() bool { return a.MD5 == "" }

func Hash(b []byte) [32]byte { return sha256.Sum256(b) }
