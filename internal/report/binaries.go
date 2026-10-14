package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
)

// BinaryRow is one ELF file the container scan inspected.
type BinaryRow struct {
	Path       string
	Weaknesses []string
	// Package is the OS package that installed it, when the lookup knew.
	Package string
}

// BinarySummary is the ELF pass of a container scan, ready to draw.
type BinarySummary struct {
	Files  int // everything walked
	Rows   []BinaryRow
	Errors []string
}

// binaryWeaknesses are the findings the summary counts, worst first. A binary
// is also described by these words in its own row.
var binaryWeaknesses = []struct {
	key, count, word string
	severe           bool
}{
	{"setuid", "setuid", "setuid", true},
	{"world-writable", "world-writable", "world-writable", true},
	{"nx-disabled", "with an executable stack", "executable stack", true},
	{"insecure-rpath", "with an insecure RPATH", "insecure RPATH", true},
	{"no-pie", "without PIE", "no PIE", false},
	{"no-relro", "without RELRO", "no RELRO", false},
	{"partial-relro", "with partial RELRO", "partial RELRO", false},
	{"no-stack-canary", "without a stack canary", "no stack canary", false},
	{"setgid", "setgid", "setgid", false},
}

func binaryWeight(r BinaryRow) int {
	w := 0
	for _, x := range r.Weaknesses {
		switch {
		case strings.HasPrefix(x, "dangerous-capability"):
			w += 3
			continue
		}
		for _, k := range binaryWeaknesses {
			if k.key == x {
				if k.severe {
					w += 3
				} else {
					w++
				}
			}
		}
	}
	return w
}

func binaryWords(r BinaryRow) string {
	var out []string
	for _, x := range r.Weaknesses {
		if c, ok := strings.CutPrefix(x, "dangerous-capability:"); ok {
			out = append(out, c+" capability")
			continue
		}
		known := false
		for _, k := range binaryWeaknesses {
			if k.key == x {
				out = append(out, k.word)
				known = true
			}
		}
		if !known {
			out = append(out, x)
		}
	}
	return strings.Join(out, " · ")
}

// RenderBinaries draws the ELF pass as one section in the container report's
// grammar. It is a summary of what the files are, not a list of findings: the
// malware verdict and the packages inside travel on their own channels.
func RenderBinaries(b BinarySummary, o Options, t *display.Terminal) string {
	s := NewStyle(t, o)
	if len(b.Rows) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString("\n" + codeSectionNote(s, "BINARIES", fmt.Sprintf("%s %s %s scanned",
		plural(len(b.Rows), "ELF file"), s.G.Sep, plural(b.Files, "file"))))

	counts := map[string]int{}
	for _, r := range b.Rows {
		for _, w := range r.Weaknesses {
			counts[w]++
		}
	}
	relro := counts["no-relro"] + counts["partial-relro"]
	var parts []string
	for _, k := range binaryWeaknesses {
		n := counts[k.key]
		switch k.key {
		case "no-relro":
			n = relro
			k.count = "without full RELRO"
		case "partial-relro":
			continue
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k.count))
		}
	}
	ind := indentFor(s)
	if len(parts) == 0 {
		out.WriteString(ind + s.Good("no hardening weaknesses found") + "\n")
	} else {
		for _, l := range wrapText(strings.Join(parts, " "+s.G.Sep+" "), s.Width-len(ind)-2) {
			out.WriteString(ind + l + "\n")
		}
	}

	rows := append([]BinaryRow(nil), b.Rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if wi, wj := binaryWeight(rows[i]), binaryWeight(rows[j]); wi != wj {
			return wi > wj
		}
		return rows[i].Path < rows[j].Path
	})
	limit := len(rows)
	if o.Verbosity == 0 {
		limit = min(limit, 5)
	}
	shown := rows[:limit]
	pathW := 0
	for _, r := range shown {
		pathW = max(pathW, display.Width(r.Path))
	}
	pathW = min(pathW+2, max(20, s.Width-len(ind)-24))
	for _, r := range shown {
		words := binaryWords(r)
		if words == "" {
			if o.Verbosity == 0 {
				continue
			}
			words = "no weaknesses"
		}
		if r.Package != "" {
			words += " " + s.G.Sep + " from " + r.Package
		}
		if s.Width < tierCompact {
			out.WriteString(ind + s.Path(s.clip(r.Path, s.Width-len(ind)-2)) + "\n" + ind + "  " + s.Dim(s.clip(words, s.Width-len(ind)-4)) + "\n")
			continue
		}
		line := ind + pad(s.Path(s.clip(r.Path, pathW-2)), pathW)
		out.WriteString(line + s.Dim(s.clip(words, max(10, codeRowWidth(s)-1-vis(line)))) + "\n")
	}
	if rest := len(rows) - limit; rest > 0 {
		out.WriteString(ind + s.Dim(fmt.Sprintf("+ %d more %s -v lists every one", rest, s.G.Sep)) + "\n")
	}
	if n := len(b.Errors); n > 0 {
		out.WriteString(ind + s.Warn(fmt.Sprintf("%d %s could not be read", n, pluralWord(n, "file", "files"))))
		if o.Verbosity >= 1 {
			out.WriteString("\n")
			for _, e := range b.Errors {
				out.WriteString(ind + s.Dim(s.clip(e, s.Width-len(ind)-2)) + "\n")
			}
		} else {
			out.WriteString(s.Dim(" "+s.G.Sep+" -v lists them") + "\n")
		}
	}
	return out.String()
}
