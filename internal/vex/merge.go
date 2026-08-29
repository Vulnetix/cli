package vex

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// merge.go combines statements from several documents, and writes the result.
//
// Writing OpenVEX rather than round-tripping each input format is deliberate:
// a merge of an OpenVEX document, a CSAF advisory and a CycloneDX VEX has no
// natural home in any one of the three, and OpenVEX is the format whose whole
// purpose is carrying statements independent of a BOM.

// Merge combines documents, newest statement per (vulnerability, product) wins.
//
// A later statement supersedes an earlier one about the same thing — that is
// what VEX is for. A vendor who published "under_investigation" in March and
// "not_affected" in June has said the second thing, and a merge that kept both
// would leave the consumer to guess.
func Merge(docs []*Document) []Statement {
	type keyed struct {
		st  Statement
		seq int
	}
	best := map[string]keyed{}
	seq := 0

	for _, doc := range docs {
		for _, st := range doc.Statements {
			if st.VulnID == "" {
				continue
			}
			for _, key := range mergeKeys(st) {
				seq++
				cur, exists := best[key]
				if !exists || supersedes(st, cur.st, seq, cur.seq) {
					best[key] = keyed{st: st, seq: seq}
				}
			}
		}
	}

	// One statement can cover several products and therefore several keys;
	// dedupe so the output carries it once.
	seen := map[string]bool{}
	out := make([]Statement, 0, len(best))
	for _, k := range best {
		id := statementIdentity(k.st)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, k.st)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VulnID != out[j].VulnID {
			return out[i].VulnID < out[j].VulnID
		}
		return statementIdentity(out[i]) < statementIdentity(out[j])
	})
	return out
}

// supersedes reports whether a replaces b for the same key.
//
// Timestamp first, because that is the assertion's own claim about when it was
// made. Ties fall back to read order, so a merge is deterministic even when
// every document omits timestamps — which many do.
func supersedes(a, b Statement, aSeq, bSeq int) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.After(b.Timestamp)
	}
	return aSeq > bSeq
}

// mergeKeys returns the (vulnerability, product) keys a statement covers.
func mergeKeys(st Statement) []string {
	if len(st.Products) == 0 {
		return []string{st.VulnID + "\x00"}
	}
	keys := make([]string, 0, len(st.Products))
	for _, p := range st.Products {
		keys = append(keys, st.VulnID+"\x00"+firstNonEmpty(p.Purl, p.ID))
	}
	return keys
}

// statementIdentity is a stable identity for deduplication.
func statementIdentity(st Statement) string {
	id := st.VulnID + "|" + string(st.Status) + "|" + st.Justification
	products := make([]string, 0, len(st.Products))
	for _, p := range st.Products {
		products = append(products, firstNonEmpty(p.Purl, p.ID))
	}
	sort.Strings(products)
	for _, p := range products {
		id += "|" + p
	}
	return id
}

// WriteOptions controls OpenVEX serialisation.
type WriteOptions struct {
	// ID is the document identifier. Generated when empty.
	ID string
	// Author is the document author.
	Author string
	// Tooling identifies what produced the document.
	Tooling string
	// Now overrides the timestamp, for deterministic tests.
	Now time.Time
}

// WriteOpenVEX serialises statements as an OpenVEX 0.2.0 document.
//
// Deliberately separate from triage.GenerateOpenVEX. That function turns the
// CLI's own triage findings into statements; this one round-trips statements
// that already exist. Sharing them would mean one function serving two callers
// with different inputs and different obligations — the triage writer may
// invent a justification for a fixed finding, and a merge must never invent
// anything the source documents did not say.
func WriteOpenVEX(statements []Statement, opts WriteOptions) ([]byte, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowStr := now.Format(time.RFC3339)

	id := opts.ID
	if id == "" {
		id = fmt.Sprintf("urn:openvex:vulnetix:merge:%s", now.Format("20060102T150405Z"))
	}
	author := opts.Author
	if author == "" {
		author = "Vulnetix"
	}
	tooling := opts.Tooling
	if tooling == "" {
		tooling = "vulnetix-cli"
	}

	stmts := make([]map[string]any, 0, len(statements))
	for _, st := range statements {
		out := map[string]any{
			"vulnerability": vulnerabilityBlock(st),
			"status":        string(st.Status),
		}
		ts := st.Timestamp
		if ts.IsZero() {
			ts = now
		}
		out["timestamp"] = ts.UTC().Format(time.RFC3339)

		if st.Justification != "" {
			out["justification"] = st.Justification
		}
		if st.ImpactStatement != "" {
			out["impact_statement"] = st.ImpactStatement
		}
		if st.ActionStatement != "" {
			out["action_statement"] = st.ActionStatement
		}
		if products := productBlocks(st); len(products) > 0 {
			out["products"] = products
		}
		stmts = append(stmts, out)
	}

	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        id,
		"author":     author,
		"timestamp":  nowStr,
		"version":    1,
		"tooling":    tooling,
		"statements": stmts,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func vulnerabilityBlock(st Statement) map[string]any {
	v := map[string]any{"name": st.VulnID}
	if len(st.Aliases) > 0 {
		aliases := append([]string(nil), st.Aliases...)
		sort.Strings(aliases)
		v["aliases"] = aliases
	}
	return v
}

func productBlocks(st Statement) []map[string]any {
	out := make([]map[string]any, 0, len(st.Products))
	for _, p := range st.Products {
		id := firstNonEmpty(p.Purl, p.ID)
		if id == "" {
			continue
		}
		block := map[string]any{"@id": id}
		if p.Purl != "" {
			block["identifiers"] = map[string]string{"purl": p.Purl}
		}
		if len(p.Versions) > 0 {
			versionsOut := make([]map[string]string, 0, len(p.Versions))
			for _, v := range p.Versions {
				versionsOut = append(versionsOut, map[string]string{"version": v})
			}
			block["versions"] = versionsOut
		}
		if len(p.Subcomponents) > 0 {
			subs := make([]map[string]string, 0, len(p.Subcomponents))
			for _, s := range p.Subcomponents {
				subs = append(subs, map[string]string{"@id": s})
			}
			block["subcomponents"] = subs
		}
		out = append(out, block)
	}
	return out
}
