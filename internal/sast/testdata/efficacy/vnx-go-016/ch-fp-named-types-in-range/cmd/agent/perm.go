package main

import (
	"io/fs"
	"strconv"
	"time"
)

type Weight int64

type Shard uint16

func perm(s string) fs.FileMode {
	m, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0o600
	}
	return fs.FileMode(m)
}

func weight(s string) Weight {
	n, _ := strconv.Atoi(s)
	return Weight(n)
}

func shard(s string) Shard {
	n, _ := strconv.ParseUint(s, 10, 16)
	return Shard(n)
}

func timeout(s string) time.Duration {
	n, _ := strconv.Atoi(s)
	return time.Duration(n) * time.Second
}
