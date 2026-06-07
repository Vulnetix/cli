package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"

	autofix "github.com/vulnetix/cli/v3/internal/fix"
)

func chooseAutofixManifest(plans []autofix.FixCandidate, manifest string, yes, pathExplicit bool) (string, error) {
	if manifest != "" || yes || pathExplicit {
		return manifest, nil
	}
	seen := map[string]bool{}
	var manifests []string
	for _, p := range plans {
		if p.SourceFile == "" || seen[p.SourceFile] {
			continue
		}
		seen[p.SourceFile] = true
		manifests = append(manifests, p.SourceFile)
	}
	sort.Strings(manifests)
	if len(manifests) <= 1 {
		return manifest, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("multiple manifests have autofix candidates; pass --sca-autofix-manifest or --yes in non-interactive mode")
	}
	fmt.Fprintln(os.Stderr, "Multiple manifests have SCA autofix candidates:")
	fmt.Fprintln(os.Stderr, "  0) all manifests")
	for i, m := range manifests {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, m)
	}
	fmt.Fprint(os.Stderr, "Choose manifest to fix [0]: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" || line == "0" {
		return "", nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(manifests) {
		return "", fmt.Errorf("invalid manifest selection %q", line)
	}
	return manifests[n-1], nil
}
