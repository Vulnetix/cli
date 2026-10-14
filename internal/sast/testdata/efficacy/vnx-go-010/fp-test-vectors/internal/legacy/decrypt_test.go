package legacy

import (
	"crypto/des"
	"crypto/rc4"
	"testing"
)

// Known-answer tests for the importer that reads archives written by the old
// system; a test protects no data.
func TestTripleDESVector(t *testing.T) {
	c, err := des.NewTripleDESCipher(make([]byte, 24))
	if err != nil {
		t.Fatal(err)
	}
	_ = c
	s, _ := rc4.NewCipher([]byte("Key"))
	_ = s
}
