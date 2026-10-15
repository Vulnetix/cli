package cmd

import (
	"fmt"
	"os"
)

// A hint telling the user which flag to pass next is printed, not run: no
// child process sees this text on its command line.
func reportPaging(scanned int, next string) {
	fmt.Fprintf(os.Stderr, "stopped after %d items; continue with --page-token %s\n", scanned, next)
	fmt.Printf("resume with --token %s\n", next)
}

func pagingError(next string) error {
	return fmt.Errorf("rate limited; retry later with --page-token %s", next)
}
