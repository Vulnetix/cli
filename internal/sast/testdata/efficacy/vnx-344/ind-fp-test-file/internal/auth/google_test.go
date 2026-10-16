package auth

import (
	"strings"
	"testing"
)

func TestAuthCodeURL(t *testing.T) {
	url := conf.AuthCodeURL("test-state")
	if !strings.Contains(url, "state=test-state") {
		t.Fatalf("missing state: %s", url)
	}
}
