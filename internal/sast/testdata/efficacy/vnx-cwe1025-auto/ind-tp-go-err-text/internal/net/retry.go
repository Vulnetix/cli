package net

import "strings"

func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
~>	if err.Error() == "connection reset by peer" {
		return true
	}
	return strings.Contains(err.Error(), "timeout")
}
