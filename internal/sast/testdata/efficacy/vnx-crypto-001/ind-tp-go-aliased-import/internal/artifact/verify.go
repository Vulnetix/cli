package artifact

import (
	cmd5 "crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// VerifyDownload checks a downloaded release archive against the published digest.
func VerifyDownload(path, published string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
~>	h := cmd5.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != published {
		return fmt.Errorf("archive digest mismatch: %s", got)
	}
	return nil
}
