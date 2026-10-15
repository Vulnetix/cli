package net

import (
	"fmt"
	"os"
)

// Point REDIS_ADDR at the cache, for example "10.30.1.5:6379".
// net.Dial("tcp", "10.30.1.6:6379") is what the old code did.

func Addr() string {
	if a := os.Getenv("REDIS_ADDR"); a != "" {
		return a
	}
	return "localhost:6379"
}

func describe(version string) string {
	return fmt.Sprintf("client %s built against 4.2.10.1", version)
}
