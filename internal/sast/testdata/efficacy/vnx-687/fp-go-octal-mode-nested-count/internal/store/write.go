package store

import (
	"os"
	"path/filepath"
	"strings"
)

// The mode is 0o644 (octal); 5000 and 600 are arguments of the nested calls
// (a repeat count and a byte), not WriteFile's permission.
func writeFixtures(root string) error {
	if err := os.WriteFile(filepath.Join(root, "big.txt"), []byte(strings.Repeat("x", 5000)), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "pad.txt"), padded(600), 0600)
}

func padded(n int) []byte { return make([]byte, n) }
