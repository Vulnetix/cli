package storage

import "testing"

func TestParseKey(t *testing.T) {
	k := "@@sample:AKIA[A-Z2-7]{16}@@"
	if !looksLikeKey(k) {
		t.Fatal("expected key")
	}
}
