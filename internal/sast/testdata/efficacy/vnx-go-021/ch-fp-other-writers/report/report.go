package report

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Write(path string, rows []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	var sb strings.Builder
	for _, r := range rows {
		fmt.Fprintf(bw, "<tr><td>%s</td></tr>\n", r)
		fmt.Fprintf(&sb, "<li>%s</li>", r)
		fmt.Fprintf(os.Stderr, "<debug>%s</debug>\n", r)
	}
	return bw.Flush()
}
