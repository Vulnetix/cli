package lib

import "strings"

func IsNotion(t string) bool { return strings.HasPrefix(t, "ntn_") || strings.HasPrefix(t, "secret_") }
