package defences

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Hint says where in a repository evidence of a given enforcement point was
// found. It is inference from files, not knowledge of what is deployed, and
// every renderer says so.
type Hint struct {
	File string
	Line int
	// What is the token that matched, e.g. "aws_wafv2_web_acl".
	What string
}

// Where renders the hint as file:line.
func (h Hint) Where() string {
	if h.Line > 0 {
		return h.File + ":" + strconv.Itoa(h.Line)
	}
	return h.File
}

type marker struct {
	kind Kind
	// names matches the base filename (exact, lower-case); empty means any file.
	names []string
	// exts restricts by extension (lower-case, with dot); empty means any.
	exts []string
	// tokens are substrings searched in the file; the first hit wins.
	tokens []string
}

// markers is deliberately small and literal. A false hint costs a reader a
// glance; an invented one costs them trust, so only unambiguous tokens are used.
var markers = []marker{
	{kind: KindAWSWAF, exts: []string{".tf", ".json", ".yaml", ".yml", ".template"}, tokens: []string{"aws_wafv2_web_acl", "AWS::WAFv2::WebACL"}},
	{kind: KindCloudflare, exts: []string{".tf"}, tokens: []string{"cloudflare_ruleset", "cloudflare_filter", "cloudflare_firewall_rule"}},
	{kind: KindModSec, exts: []string{".conf"}, tokens: []string{"SecRuleEngine", "SecRule "}},
	{kind: KindNginx, names: []string{"nginx.conf"}},
	{kind: KindNginx, names: []string{"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}, tokens: []string{"FROM nginx", "image: nginx", "image: \"nginx"}},
	{kind: KindNginx, exts: []string{".yaml", ".yml"}, tokens: []string{"nginx.ingress.kubernetes.io"}},
	{kind: KindSuricata, names: []string{"suricata.yaml", "suricata.yml"}},
	{kind: KindSnort, names: []string{"snort.conf", "snort.lua"}},
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".vulnetix": true,
	".terraform": true, "dist": true, "target": true, ".venv": true, "__pycache__": true,
}

const (
	maxStackFiles = 4000
	maxStackBytes = 512 * 1024
)

// InferStack looks for evidence in the repository of which enforcement points
// are in front of the application, so the formats that fit can be listed first.
// The walk is bounded in both file count and file size.
func InferStack(root string) map[Kind]Hint {
	found := map[Kind]Hint{}
	seen := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		seen++
		if seen > maxStackFiles {
			return filepath.SkipAll
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxStackBytes || !info.Mode().IsRegular() {
			return nil
		}
		base := strings.ToLower(d.Name())
		ext := strings.ToLower(filepath.Ext(base))
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		for _, m := range markers {
			if _, done := found[m.kind]; done || !m.applies(base, ext) {
				continue
			}
			if len(m.tokens) == 0 {
				found[m.kind] = Hint{File: rel, What: d.Name()}
				continue
			}
			if h, ok := firstToken(path, rel, m.tokens); ok {
				found[m.kind] = h
			}
		}
		return nil
	})
	return found
}

func (m marker) applies(base, ext string) bool {
	if len(m.names) > 0 && !contains(m.names, base) {
		return false
	}
	if len(m.exts) > 0 && !contains(m.exts, ext) {
		return false
	}
	return len(m.names) > 0 || len(m.exts) > 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func firstToken(path, rel string, tokens []string) (Hint, bool) {
	f, err := os.Open(path)
	if err != nil {
		return Hint{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxStackBytes)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, tok := range tokens {
			if strings.Contains(line, tok) {
				return Hint{File: rel, Line: n, What: strings.TrimSpace(tok)}, true
			}
		}
	}
	return Hint{}, false
}
