package vex

import (
	"strings"
	"time"
)

// console.go reads the VEX statements the Vulnetix console holds as rules.
//
// A VexSource of type tea, s3 or git is fetched by the console, which turns
// each statement into a suppression rule keyed by vulnerability and product.
// cli.suppressions-get returns those rules with the statement's status and
// justification, and this turns them back into statements so a scan applies
// them with the same matching, annotation and counts as a --vex document. They
// are not a second matching engine.
//
// The console already decided what a statement means (a fixed statement is not
// a rule; a rule is a false positive, a mitigation or a decision not to fix),
// so a rule's status is taken as given. A rule with a status this package does
// not know is skipped rather than guessed at.

// FormatConsole is the Format of a statement read from the console.
const FormatConsole Format = "vulnetix-console"

// ConsolePathPrefix starts the Path of a console statement's source, followed by
// the VexSource that owns it.
const ConsolePathPrefix = "vulnetix-console:"

// ConsoleRule is one console rule, as the CLI read it from the API.
type ConsoleRule struct {
	VulnerabilityID string
	ProductPurl     string
	ProductPurlBase string
	Status          string
	Justification   string
	// Reason is the rule's own text; it supports a not_affected status as the
	// impact statement.
	Reason string
	// Source is the VexSource's name, SourceType its type.
	Source     string
	SourceType string
	// SourceRef and DocumentID locate the statement in its document.
	SourceRef  string
	DocumentID string
	// Timestamp is when the statement was made, unix seconds.
	Timestamp int64
}

// ConsoleDocument turns console rules into one document of statements, and
// reports how many rules it could not use.
func ConsoleDocument(rules []ConsoleRule) (doc *Document, skipped int) {
	doc = &Document{Format: FormatConsole, ID: "vulnetix-console", Author: "Vulnetix console", Path: "vulnetix-console"}
	for _, r := range rules {
		st := Status(strings.ToLower(strings.TrimSpace(r.Status)))
		if strings.TrimSpace(r.VulnerabilityID) == "" || !st.Valid() {
			skipped++
			continue
		}
		name := r.Source
		if name == "" {
			name = "unnamed"
		}
		s := Statement{
			VulnID:        strings.TrimSpace(r.VulnerabilityID),
			Status:        st,
			Justification: r.Justification,
			Source: StatementSource{
				Path:       ConsolePathPrefix + "VexSource/" + name,
				Format:     FormatConsole,
				DocumentID: r.DocumentID,
				Author:     "VexSource/" + name,
			},
		}
		if st == StatusNotAffected {
			s.ImpactStatement = r.Reason
		} else {
			s.ActionStatement = r.Reason
		}
		// The narrowest product the console recorded: a statement about one
		// version must not become one about every version.
		if p := firstNonEmpty(r.ProductPurl, r.ProductPurlBase); p != "" {
			s.Products = []Product{{Purl: p}}
		}
		if r.Timestamp > 0 {
			s.Timestamp = time.Unix(r.Timestamp, 0).UTC()
		}
		doc.Statements = append(doc.Statements, s)
	}
	return doc, skipped
}

// DedupeConsole drops from console the statements already said by local
// documents (--vex files, directories and URLs, and path and urls VexSources),
// or said twice by the console itself, and returns how many it dropped.
//
// A local statement covers a console one when it is about the same
// vulnerability with the same status and the same product, or about the same
// package with no version, which speaks about every version. A local statement
// about one version does not cover a console statement about all of them:
// dropping that one would narrow what the console decided.
func DedupeConsole(console *Document, local []*Document) (kept *Document, dropped int) {
	if console == nil {
		return nil, 0
	}
	exact := map[string]bool{}
	anyVersion := map[string]bool{}
	wide := map[string]bool{}
	for _, d := range local {
		for _, st := range d.Statements {
			for _, id := range statementIDs(st) {
				base := id + "|" + string(st.Status)
				if len(st.Products) == 0 {
					wide[base] = true
					continue
				}
				for _, p := range st.Products {
					purl := strings.ToLower(firstNonEmpty(p.Purl, p.ID))
					exact[base+"|"+purl] = true
					if purlVersion(purl) == "" {
						anyVersion[base+"|"+purlWithoutVersion(purl)] = true
					}
				}
			}
		}
	}

	out := *console
	out.Statements = nil
	seen := map[string]bool{}
	for _, st := range console.Statements {
		id := strings.ToUpper(st.VulnID)
		base := id + "|" + string(st.Status)
		purl := ""
		if len(st.Products) > 0 {
			purl = strings.ToLower(firstNonEmpty(st.Products[0].Purl, st.Products[0].ID))
		}
		key := base + "|" + purl
		covered := seen[key] || exact[key] || (purl == "" && wide[base]) || (purl != "" && anyVersion[base+"|"+purlWithoutVersion(purl)])
		if covered {
			dropped++
			continue
		}
		seen[key] = true
		out.Statements = append(out.Statements, st)
	}
	return &out, dropped
}

// statementIDs are the identifiers a statement is known by, upper-cased.
func statementIDs(st Statement) []string {
	ids := []string{strings.ToUpper(st.VulnID)}
	for _, a := range st.Aliases {
		ids = append(ids, strings.ToUpper(a))
	}
	return ids
}
