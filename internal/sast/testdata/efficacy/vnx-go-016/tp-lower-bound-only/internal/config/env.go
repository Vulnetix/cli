package config

import (
	"os"
	"strconv"
)

// A positive check is not a range check: WORKERS=4294967296 passes n > 0 and
// truncates to 0.
func Workers(def int32) int32 {
	if v := os.Getenv("WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
~>			return int32(n)
		}
	}
	return def
}
