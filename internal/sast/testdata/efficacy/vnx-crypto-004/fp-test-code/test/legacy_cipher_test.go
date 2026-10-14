package legacy

import (
	"crypto/des"
	"testing"
)

func TestReadsOldBlobs(t *testing.T) {
	block, err := des.NewTripleDESCipher(make([]byte, 24))
	if err != nil {
		t.Fatal(err)
	}
	_ = block
}
