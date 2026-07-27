package analyze

// The egress collector: every host this repository reaches out to.
//
// The other collectors describe what the repository IS. This one describes where
// it TALKS TO — the registries a build pulls from, the APIs the code calls, the
// endpoints a workflow posts to, the DNS names an IaC file declares. On a threat
// model that is the outbound half of the attack surface, and until now it was
// the half nothing wrote down.
//
// It walks the tree itself rather than reusing the file collector's list, because
// that list is source files with a tree-sitter language: no Dockerfile, no
// workflow YAML, no `.tf` — exactly the files where the interesting hosts live.
//
// One node per HOST, not per sighting. A CDN referenced from forty files is one
// egress destination; forty nodes would say the same thing forty times, which is
// the mistake that buried the threat-model canvas under dependency nodes.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// maxEgressHosts caps the node count. A repository past this is not going to be
// understood better by the 501st hostname, and the cap is reported rather than
// applied silently — "these are the hosts" and "these are some of the hosts" are
// different claims.
const maxEgressHosts = 500

// maxEgressFileBytes is deliberately below the file collector's 1 MiB: a file
// larger than this holding hostnames is minified output or a vendored blob, and
// scanning it produces CDN noise rather than intent.
const maxEgressFileBytes = 512 << 10

var (
	// scheme://host — the unambiguous case, and the only one that records a scheme.
	egressURLPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]{1,15})://([^\s"'` + "`" + `<>()\[\]{},\\|^]+)`)

	// A bare hostname anywhere in the text. Nearly everything it matches is
	// rejected downstream by the TLD gate; that is the intended division of
	// labour — match loosely here, decide in isEgressHost.
	egressHostPattern = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b`)

	// Comment strippers that do NOT eat URLs. The contract collector's version
	// takes `//` to end-of-line unconditionally, which removes exactly the thing
	// this collector is looking for: `"https://api.acme.com"` is a URL in a string
	// literal, not a comment. So `//` only opens a comment when the character
	// before it is neither `:` nor part of a word.
	egressLineComment  = regexp.MustCompile(`(?m)(^|[^:\w])//[^\n]*`)
	egressHashComment  = regexp.MustCompile(`(?m)(^|\s)#[^\n]*`)
	egressBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

	// A single-line string literal in any of the three quoting styles the
	// languages we parse use. Source code's bare hostnames are only read from
	// inside these.
	quotedLiteral = regexp.MustCompile("\"[^\"\\n]*\"|'[^'\\n]*'|`[^`\\n]*`")
)

// Last labels that are real TLDs and also ordinary file extensions. A bare
// `install.sh` is a script far more often than it is Saint Helena, and reading it
// as a destination puts a fake host in every repository with a shell script.
// Costs us the rare genuine `acme.sh`-style host, which is the right trade: a
// wrong egress host is worse than a missing one, because the whole point of the
// count is that somebody acts on it.
var egressFileExtensionTLDs = map[string]bool{
	"sh": true, "rs": true, "pl": true, "zip": true, "mov": true, "md": true,
	"py": true, "in": true, "so": true, "cc": true, "pm": true, "ps": true,
	"sc": true,
}

// egressSighting is one place a host was written down. Every pass — code, config,
// manifest — reports through this shape, so a host found three ways is one
// destination with three pieces of evidence rather than three nodes.
type egressSighting struct {
	Host   string
	Scheme string
	Source string
	Path   string
	Line   int

	// How strongly this sighting says "the code talks to this". See the tiers in
	// egress_code.go.
	Evidence string

	// Set on a call-site sighting: the call that named the host. This is the
	// difference between "acme-cdn.io appears in the source" and "http.Get is
	// pointed at acme-cdn.io".
	Callee string

	// Set on a config sighting: the key the host was the value of, so a reader
	// can find it without opening the file.
	KeyPath string
}

type egressRecorder func(egressSighting)

// egressHost is one destination, with everything known about how it was found.
type egressHost struct {
	Host        string
	Occurrences int
	FirstPath   string
	FirstLine   int

	// Source classes, URL schemes, evidence tiers and the calls that named it,
	// as sets while collecting. Order is imposed at the end so two runs over the
	// same tree produce the same report.
	sources  map[string]bool
	schemes  map[string]bool
	evidence map[string]bool
	callees  map[string]bool
	keyPaths map[string]bool

	// Set when the host came from a dependency rather than from a file: the PURL
	// that named it. Kept so the node can still be traced to its manifest.
	Purl string
}

type egressStats struct {
	hosts []*egressHost

	// The cap was hit. Carried into the report's graph truncation.
	truncated bool

	filesScanned int
}

func collectEgress(root string, deps *depStats) *egressStats {
	st := &egressStats{}
	byHost := map[string]*egressHost{}

	engine := reachability.NewEngine()
	ctx := context.Background()

	record := func(s egressSighting) {
		h, ok := byHost[s.Host]
		if !ok {
			if len(byHost) >= maxEgressHosts {
				st.truncated = true

				return
			}
			h = &egressHost{
				Host: s.Host, FirstPath: s.Path, FirstLine: s.Line,
				sources: map[string]bool{}, schemes: map[string]bool{},
				evidence: map[string]bool{}, callees: map[string]bool{},
				keyPaths: map[string]bool{},
			}
			byHost[s.Host] = h
		}
		h.Occurrences++

		// The strongest evidence wins the node's `firstPath`: a reader chasing a
		// host wants the line that calls it, not the first file alphabetically
		// that happened to mention it.
		if s.Evidence != "" && (bestEvidence(h.evidence) == "" ||
			egressEvidenceRank[s.Evidence] < egressEvidenceRank[bestEvidence(h.evidence)]) {
			h.FirstPath, h.FirstLine = s.Path, s.Line
		}

		addTo := func(set map[string]bool, value string) {
			if value != "" {
				set[value] = true
			}
		}
		addTo(h.sources, s.Source)
		addTo(h.schemes, s.Scheme)
		addTo(h.evidence, s.Evidence)
		addTo(h.callees, s.Callee)
		addTo(h.keyPaths, s.KeyPath)
	}

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}

			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		source := classifyEgressSource(rel)
		language := string(treesitter.LanguageForPath(path))

		// Nothing else is worth opening. A file that is neither source nor
		// configuration is a licence, a fixture or a binary, and the hostnames in
		// those are somebody else's.
		if language == "" && source == egressSourceCode {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxEgressFileBytes {
			return nil
		}

		body, rerr2 := os.ReadFile(path)
		if rerr2 != nil || isBinary(body) {
			return nil
		}
		st.filesScanned++

		// Source code goes to the parser, which is the only thing that can tell a
		// destination from a dotted identifier. Comments come out first, for the
		// same reason the contract collector strips them: a licence header or a
		// doc link is not somewhere this code reaches.
		if language != "" {
			stripped := []byte(stripEgressComments(string(body), language))
			scanEgressCode(ctx, engine, treesitter.LanguageID(language), stripped, rel, record)

			return nil
		}

		// Everything else is configuration, and every format here has a parser or
		// a grammar of its own. Reading them as text is what produced `http.host`
		// and `steps.scan.outputs.total` — expression syntax, not hostnames.
		scanEgressConfig(string(body), source, rel, record)

		return nil
	})

	// Dependencies resolved from somewhere other than a registry name a host by
	// definition — the resolver asks DNS for it. They are merged into the same
	// set so a host appearing both in go.mod and in code is one destination.
	if deps != nil {
		for _, dep := range deps.deps {
			host, ok := egressHostFromDependency(dep.Purl, purlName(dep.Purl))
			if !ok {
				continue
			}
			record(egressSighting{
				Host: host, Source: egressSourceManifest, Path: dep.ManifestPath,
				Evidence: egressEvidenceManifest,
			})
			if h := byHost[host]; h != nil && h.Purl == "" {
				h.Purl = dep.Purl
			}
		}
	}

	st.hosts = make([]*egressHost, 0, len(byHost))
	for _, h := range byHost {
		st.hosts = append(st.hosts, h)
	}
	sort.Slice(st.hosts, func(i, j int) bool { return st.hosts[i].Host < st.hosts[j].Host })

	return st
}

// stripEgressComments removes comments without removing URLs. See the pattern
// definitions above for why the contract collector's stripper cannot be reused.
func stripEgressComments(src, language string) string {
	switch language {
	case "python", "ruby", "bash", "yaml", "toml", "dockerfile", "hcl", "terraform":
		return egressHashComment.ReplaceAllString(src, "$1")
	default:
		src = egressBlockComment.ReplaceAllString(src, "")

		return egressLineComment.ReplaceAllString(src, "$1")
	}
}

// scanEgressText pulls hosts out of one file's text: URLs first, so their scheme
// is kept, then bare hostnames.
//
// The URL spans are blanked before the bare pass. Without that, every URL path
// contributes its own file name — `…/install.sh` reads as a host in Saint
// Helena — and the count fills up with things nobody resolves.
//
// SOURCE CODE IS SCANNED DIFFERENTLY, and it has to be. `p.name`, `time.now`,
// `resp.data` and `err.report` are field accesses; .name, .now, .data and .report
// are also real TLDs, so a bare-hostname regex over Go or C reports hundreds of
// egress destinations that do not exist. In code a bare host therefore only
// counts when a string literal contains NOTHING BUT that host (optionally with a
// port). Anything reached through a scheme still counts wherever it appears, and
// an import path like "github.com/vulnetix/cli/v3" correctly does not — that is
// where the module came from, not somewhere this code calls.
func scanEgressText(text, source, path string, quotedOnly bool, evidence string,
	record egressRecorder) {
	lineNo := 0
	for line := range strings.SplitSeq(text, "\n") {
		lineNo++

		seenInLine := map[string]bool{}
		for _, m := range egressURLPattern.FindAllStringSubmatch(line, -1) {
			host := normaliseHost(m[2])
			if !isEgressHost(host) {
				continue
			}
			seenInLine[host] = true
			record(egressSighting{
				Host: host, Scheme: strings.ToLower(m[1]), Source: source,
				Path: path, Line: lineNo, Evidence: evidence,
			})
		}

		remainder := egressURLPattern.ReplaceAllString(line, " ")

		if quotedOnly {
			for _, literal := range quotedLiteral.FindAllString(remainder, -1) {
				host, hasPort, ok := literalHost(literal)
				if !ok || seenInLine[host] || !isEgressHost(host) || hasFileExtensionTLD(host) {
					continue
				}

				// No scheme, no port, no call site: the tighter TLD gate applies,
				// or every metric id in the file (`business.dependencies.total`,
				// `graph.symbols.total`) reads as a destination.
				if !hasPort && !isCommonNetworkTLD(host) {
					continue
				}

				// A portless bare literal in source code is not distinguishable
				// from a dotted identifier: `"business.dependencies.direct"` is a
				// metric id, `"application.mk"` a file name, and .direct and .mk
				// are both real TLDs. A port makes it a destination — and so does
				// the file importing something that can open a socket, which is
				// what the network-import tier means.
				if source == egressSourceCode && !hasPort && evidence != egressEvidenceNetworkImport {
					continue
				}

				seenInLine[host] = true
				record(egressSighting{
					Host: host, Source: source, Path: path, Line: lineNo, Evidence: evidence,
				})
			}

			continue
		}

		for _, m := range egressHostPattern.FindAllStringSubmatch(remainder, -1) {
			host := normaliseHost(m[1])
			if seenInLine[host] || !isEgressHost(host) || hasFileExtensionTLD(host) ||
				!isCommonNetworkTLD(host) {
				continue
			}
			seenInLine[host] = true
			record(egressSighting{
				Host: host, Source: source, Path: path, Line: lineNo, Evidence: evidence,
			})
		}
	}
}

// literalHost returns the host a quoted string literal consists of, whether it
// carried a port, and false when the literal is anything more than a host — a
// path, a sentence, a format string, an import path.
func literalHost(literal string) (host string, hasPort, ok bool) {
	s := strings.ToLower(strings.TrimSpace(strings.Trim(literal, "\"'`")))
	s = strings.TrimSuffix(s, ".")

	if head, port, cut := strings.Cut(s, ":"); cut {
		if port == "" || strings.TrimLeft(port, "0123456789") != "" {
			return "", false, false
		}
		s, hasPort = head, true
	}

	if s == "" || strings.ContainsAny(s, "/\\ \t?#@%*{}$") {
		return "", false, false
	}

	return s, hasPort, true
}

func hasFileExtensionTLD(host string) bool {
	labels := strings.Split(host, ".")

	return len(labels) == 2 && egressFileExtensionTLDs[labels[len(labels)-1]]
}

// isBinary is the cheap check: a NUL byte in the first few KiB. Reading a
// compiled artefact as text produces hostname-shaped garbage, and a repository
// with committed binaries would otherwise report egress it does not have.
func isBinary(body []byte) bool {
	head := body
	if len(head) > 8<<10 {
		head = head[:8<<10]
	}

	return slices.Contains(head, 0)
}

// graphNodes turns the collected hosts into graph nodes. Properties carry the
// provenance — where it was first seen, how often, from what kind of file —
// because "acme-cdn.io is egress" is only actionable next to "declared in
// .github/workflows/release.yml".
func (st *egressStats) graphNodes() []Node {
	out := make([]Node, 0, len(st.hosts))
	for _, h := range st.hosts {
		props := map[string]any{
			"occurrences": h.Occurrences,
			"sources":     sortedKeys(h.sources),

			// The strongest thing known about this host, and everything known.
			// "the code calls it" and "a YAML file mentions it" are both worth
			// recording and must not read as the same claim.
			"evidence":    bestEvidence(h.evidence),
			"evidenceAll": sortedKeys(h.evidence),
		}
		if len(h.callees) > 0 {
			props["callees"] = sortedKeys(h.callees)
		}
		if len(h.keyPaths) > 0 {
			props["keyPaths"] = sortedKeys(h.keyPaths)
		}
		if len(h.schemes) > 0 {
			props["schemes"] = sortedKeys(h.schemes)
		}
		if h.FirstPath != "" {
			props["firstPath"] = h.FirstPath
		}
		if h.FirstLine > 0 {
			props["firstLine"] = h.FirstLine
		}

		out = append(out, Node{
			ID:            "egress_domain:" + h.Host,
			Kind:          "egress_domain",
			Name:          h.Host,
			QualifiedName: h.Host,
			Path:          h.FirstPath,
			Purl:          h.Purl,
			Properties:    props,
		})
	}

	return out
}

// egressDependencyNodeID is the graph node id a dependency takes when its name is
// a host we resolve, and "" when it is an ordinary registry package.
//
// Every place that refers to a dependency node has to agree with this — the
// dependency node, the repo's `depends_on` edge, and the cross-repo join key —
// or a dependency ends up pointing at a node that is not in the graph.
func egressDependencyNodeID(purl string) string {
	host, ok := egressHostFromDependency(purl, purlName(purl))
	if !ok {
		return ""
	}

	return "egress_domain:" + host
}
