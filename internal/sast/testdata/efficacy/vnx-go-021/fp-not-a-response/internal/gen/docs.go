package gen

import (
	"fmt"
	"os"
	"strings"
)

type Rule struct {
	ID, Name, Note string
}

// Generating documentation into a builder, a file or stdout is not HTML
// output to a browser.
func Write(rules []Rule) error {
	var b strings.Builder
	for _, r := range rules {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td></tr>\n", r.ID, r.Name)
		fmt.Fprintf(&b, "{{< callout type=\"info\" >}}\n%s\n{{< /callout >}}\n", r.Note)
	}
	f, err := os.Create("rules.html")
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "<table>%s</table>", b.String())
	fmt.Fprintf(os.Stdout, "<b>%d</b> rules written\n", len(rules))
	fmt.Fprintf(os.Stderr, "<warn>%s</warn>\n", "done")
	return nil
}
