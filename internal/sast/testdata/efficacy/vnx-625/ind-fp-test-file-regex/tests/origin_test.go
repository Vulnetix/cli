package web

import (
	"regexp"
	"testing"
)

func TestSloppy(t *testing.T) {
	re := regexp.MustCompile(`^https://[a-z0-9-]+\.example\.com`)
	_ = re
}
