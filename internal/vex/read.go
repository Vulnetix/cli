package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Detect identifies the VEX serialisation of a document.
//
// Order matters. A CycloneDX VEX document is a CycloneDX document, so it is
// checked by bomFormat before anything else; CSAF announces itself with a
// document.category of csaf_vex; OpenVEX by its @context. A document that
// answers to none of them is not VEX, and saying so is better than guessing.
func Detect(data []byte) Format {
	var probe struct {
		Context   string `json:"@context"`
		BOMFormat string `json:"bomFormat"`
		Document  struct {
			Category string `json:"category"`
		} `json:"document"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return FormatUnknown
	}
	switch {
	case probe.BOMFormat == "CycloneDX":
		return FormatCycloneDX
	case strings.Contains(probe.Context, "openvex.dev"):
		return FormatOpenVEX
	case strings.Contains(strings.ToLower(probe.Document.Category), "vex"):
		return FormatCSAF
	default:
		return FormatUnknown
	}
}

// Load reads and parses a VEX document from a file.
func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := LoadBytes(data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// LoadBytes parses a VEX document from bytes.
func LoadBytes(data []byte, path string) (*Document, error) {
	switch Detect(data) {
	case FormatOpenVEX:
		return parseOpenVEX(data, path)
	case FormatCycloneDX:
		return parseCDXVEX(data, path)
	case FormatCSAF:
		return parseCSAFVEX(data, path)
	default:
		return nil, fmt.Errorf("not a recognised VEX document: expected OpenVEX, CycloneDX VEX or CSAF VEX")
	}
}

// LoadAll reads every VEX document under the given paths.
//
// A path may be a file or a directory; directories are walked one level deep
// for .json files. A file that is not VEX is skipped rather than fatal, because
// the usual invocation is `--vex .vulnetix/` and that directory also holds
// SBOMs and SARIF — refusing to run because a sibling file is not VEX would be
// obstructive. A file that IS VEX but fails to parse is an error, because the
// user pointed at it deliberately.
func LoadAll(paths []string) ([]*Document, []string, error) {
	var (
		docs    []*Document
		skipped []string
	)
	seen := map[string]bool{}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			doc, err := Load(p)
			if err != nil {
				return nil, nil, err
			}
			docs = append(docs, doc)
			continue
		}

		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				continue
			}
			names = append(names, e.Name())
		}
		// Deterministic order: which of two conflicting statements wins is
		// decided by timestamp, but a tie must not depend on readdir order.
		sort.Strings(names)

		for _, name := range names {
			full := filepath.Join(p, name)
			if seen[full] {
				continue
			}
			seen[full] = true
			data, err := os.ReadFile(full)
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					skipped = append(skipped, full+": "+err.Error())
					continue
				}
				return nil, nil, err
			}
			if Detect(data) == FormatUnknown {
				skipped = append(skipped, full)
				continue
			}
			doc, err := LoadBytes(data, full)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", full, err)
			}
			docs = append(docs, doc)
		}
	}
	return docs, skipped, nil
}

// ── OpenVEX 0.2.0 ───────────────────────────────────────────────────────────

func parseOpenVEX(data []byte, path string) (*Document, error) {
	var raw struct {
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Vulnerability struct {
				Name    string   `json:"name"`
				ID      string   `json:"@id"`
				Aliases []string `json:"aliases"`
			} `json:"vulnerability"`
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
			Timestamp       string `json:"timestamp"`
			Products        []struct {
				ID          string            `json:"@id"`
				Identifiers map[string]string `json:"identifiers"`
				Versions    []struct {
					Version string `json:"version"`
				} `json:"versions"`
				Subcomponents []struct {
					ID          string            `json:"@id"`
					Identifiers map[string]string `json:"identifiers"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing OpenVEX: %w", err)
	}

	docTime := parseTime(raw.Timestamp)
	doc := &Document{Format: FormatOpenVEX, ID: raw.ID, Author: raw.Author, Path: path}
	src := StatementSource{Path: path, Format: FormatOpenVEX, DocumentID: raw.ID, Author: raw.Author}

	for _, rs := range raw.Statements {
		// The identifier lives in `name` per the spec, but `@id` carries it in
		// documents written against earlier drafts and by several generators.
		id := normalizeVulnID(firstNonEmpty(rs.Vulnerability.Name, rs.Vulnerability.ID))

		st := Statement{
			VulnID:          id,
			Status:          Status(rs.Status),
			Justification:   rs.Justification,
			ImpactStatement: rs.ImpactStatement,
			ActionStatement: rs.ActionStatement,
			Timestamp:       firstTime(parseTime(rs.Timestamp), docTime),
			Source:          src,
		}
		for _, alias := range rs.Vulnerability.Aliases {
			if a := normalizeVulnID(alias); a != "" && a != id {
				st.Aliases = append(st.Aliases, a)
			}
		}
		for _, rp := range rs.Products {
			p := Product{ID: rp.ID, Purl: purlFrom(rp.ID, rp.Identifiers)}
			for _, v := range rp.Versions {
				if v.Version != "" {
					p.Versions = append(p.Versions, v.Version)
				}
			}
			for _, sc := range rp.Subcomponents {
				if purl := purlFrom(sc.ID, sc.Identifiers); purl != "" {
					p.Subcomponents = append(p.Subcomponents, purl)
				}
			}
			st.Products = append(st.Products, p)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// purlFrom extracts a purl from an OpenVEX product identifier.
//
// The spec puts it in identifiers.purl, but the overwhelming majority of
// documents in the wild put the purl straight in @id, so both are read.
func purlFrom(id string, identifiers map[string]string) string {
	if p, ok := identifiers["purl"]; ok && p != "" {
		return p
	}
	if strings.HasPrefix(id, "pkg:") {
		return id
	}
	return ""
}

// ── CycloneDX VEX ───────────────────────────────────────────────────────────

// cdxStateToStatus maps a CycloneDX analysis state onto a VEX status.
//
// CycloneDX has six states to OpenVEX's four. exploitable and in_triage are the
// two that do not map cleanly: exploitable is a stronger claim than "affected"
// but implies it, and in_triage is exactly under_investigation. false_positive
// and not_affected both mean the finding does not apply.
var cdxStateToStatus = map[string]Status{
	"resolved":               StatusFixed,
	"resolved_with_pedigree": StatusFixed,
	"exploitable":            StatusAffected,
	"in_triage":              StatusUnderInvestigation,
	"false_positive":         StatusNotAffected,
	"not_affected":           StatusNotAffected,
}

func parseCDXVEX(data []byte, path string) (*Document, error) {
	var raw struct {
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Authors   []struct {
				Name string `json:"name"`
			} `json:"authors"`
			Component struct {
				Purl string `json:"purl"`
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BOMRef string `json:"bom-ref"`
			Purl   string `json:"purl"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID         string `json:"id"`
			References []struct {
				ID string `json:"id"`
			} `json:"references"`
			Analysis *struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Response      []string `json:"response"`
				Detail        string   `json:"detail"`
			} `json:"analysis"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
			Updated string `json:"updated"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing CycloneDX VEX: %w", err)
	}

	// bom-ref → purl, so `affects` can name a product rather than an opaque ref.
	purlByRef := make(map[string]string, len(raw.Components))
	for _, c := range raw.Components {
		if c.BOMRef != "" && c.Purl != "" {
			purlByRef[c.BOMRef] = c.Purl
		}
	}

	author := ""
	if len(raw.Metadata.Authors) > 0 {
		author = raw.Metadata.Authors[0].Name
	}
	docTime := parseTime(raw.Metadata.Timestamp)
	doc := &Document{Format: FormatCycloneDX, ID: raw.SerialNumber, Author: author, Path: path}
	src := StatementSource{Path: path, Format: FormatCycloneDX, DocumentID: raw.SerialNumber, Author: author}

	for _, v := range raw.Vulnerabilities {
		// A vulnerability entry with no analysis block is a finding, not an
		// assertion about one. Reading it as VEX would turn every SBOM's
		// vulnerability list into a pile of statements asserting nothing.
		if v.Analysis == nil || v.Analysis.State == "" {
			continue
		}
		status, ok := cdxStateToStatus[v.Analysis.State]
		if !ok {
			status = Status(v.Analysis.State)
		}

		st := Statement{
			VulnID:        normalizeVulnID(v.ID),
			Status:        status,
			Justification: v.Analysis.Justification,
			Timestamp:     firstTime(parseTime(v.Updated), docTime),
			Source:        src,
		}
		// CycloneDX puts supporting prose in analysis.detail regardless of
		// state; which VEX field it corresponds to depends on the state.
		if status == StatusAffected {
			st.ActionStatement = v.Analysis.Detail
			if st.ActionStatement == "" && len(v.Analysis.Response) > 0 {
				st.ActionStatement = strings.Join(v.Analysis.Response, ", ")
			}
		} else {
			st.ImpactStatement = v.Analysis.Detail
		}
		for _, r := range v.References {
			if a := normalizeVulnID(r.ID); a != "" && a != st.VulnID {
				st.Aliases = append(st.Aliases, a)
			}
		}
		for _, a := range v.Affects {
			p := Product{ID: a.Ref}
			if purl, ok := purlByRef[a.Ref]; ok {
				p.Purl = purl
			} else if strings.HasPrefix(a.Ref, "pkg:") {
				p.Purl = a.Ref
			}
			st.Products = append(st.Products, p)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

// ── CSAF 2.0 VEX ────────────────────────────────────────────────────────────

func parseCSAFVEX(data []byte, path string) (*Document, error) {
	var raw struct {
		Document struct {
			Title    string `json:"title"`
			Tracking struct {
				ID                 string `json:"id"`
				CurrentReleaseDate string `json:"current_release_date"`
			} `json:"tracking"`
			Publisher struct {
				Name string `json:"name"`
			} `json:"publisher"`
		} `json:"document"`
		ProductTree struct {
			FullProductNames []csafProduct `json:"full_product_names"`
			Branches         []csafBranch  `json:"branches"`
			Relationships    []struct {
				FullProductName csafProduct `json:"full_product_name"`
			} `json:"relationships"`
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
			IDs []struct {
				Text string `json:"text"`
			} `json:"ids"`
			ProductStatus struct {
				KnownNotAffected   []string `json:"known_not_affected"`
				KnownAffected      []string `json:"known_affected"`
				Fixed              []string `json:"fixed"`
				UnderInvestigation []string `json:"under_investigation"`
			} `json:"product_status"`
			Threats []struct {
				Category   string   `json:"category"`
				Details    string   `json:"details"`
				ProductIDs []string `json:"product_ids"`
			} `json:"threats"`
			Remediations []struct {
				Category   string   `json:"category"`
				Details    string   `json:"details"`
				ProductIDs []string `json:"product_ids"`
			} `json:"remediations"`
			Flags []struct {
				Label      string   `json:"label"`
				ProductIDs []string `json:"product_ids"`
			} `json:"flags"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing CSAF VEX: %w", err)
	}

	// CSAF names products by an opaque product_id and defines the purl
	// elsewhere in the product tree, so the tree has to be flattened before any
	// statement can say what it is about.
	purlByProductID := map[string]string{}
	collectCSAFProducts(raw.ProductTree.FullProductNames, purlByProductID)
	collectCSAFBranches(raw.ProductTree.Branches, purlByProductID)
	for _, rel := range raw.ProductTree.Relationships {
		collectCSAFProducts([]csafProduct{rel.FullProductName}, purlByProductID)
	}

	author := raw.Document.Publisher.Name
	docTime := parseTime(raw.Document.Tracking.CurrentReleaseDate)
	doc := &Document{Format: FormatCSAF, ID: raw.Document.Tracking.ID, Author: author, Path: path}
	src := StatementSource{Path: path, Format: FormatCSAF, DocumentID: raw.Document.Tracking.ID, Author: author}

	for _, v := range raw.Vulnerabilities {
		id := normalizeVulnID(v.CVE)
		if id == "" && len(v.IDs) > 0 {
			id = normalizeVulnID(v.IDs[0].Text)
		}

		// CSAF carries the justification in a flag and the prose in a threat or
		// remediation, all keyed by product id, so they are indexed before the
		// per-status walk rather than re-scanned for each product.
		justificationByProduct := map[string]string{}
		for _, f := range v.Flags {
			for _, pid := range f.ProductIDs {
				justificationByProduct[pid] = f.Label
			}
		}
		impactByProduct := map[string]string{}
		for _, th := range v.Threats {
			if th.Category != "impact" {
				continue
			}
			for _, pid := range th.ProductIDs {
				impactByProduct[pid] = th.Details
			}
		}
		actionByProduct := map[string]string{}
		for _, r := range v.Remediations {
			for _, pid := range r.ProductIDs {
				actionByProduct[pid] = r.Details
			}
		}

		add := func(productIDs []string, status Status) {
			for _, pid := range productIDs {
				st := Statement{
					VulnID:          id,
					Status:          status,
					Justification:   justificationByProduct[pid],
					ImpactStatement: impactByProduct[pid],
					ActionStatement: actionByProduct[pid],
					Timestamp:       docTime,
					Source:          src,
					Products: []Product{{
						ID:   pid,
						Purl: purlByProductID[pid],
					}},
				}
				doc.Statements = append(doc.Statements, st)
			}
		}
		add(v.ProductStatus.KnownNotAffected, StatusNotAffected)
		add(v.ProductStatus.KnownAffected, StatusAffected)
		add(v.ProductStatus.Fixed, StatusFixed)
		add(v.ProductStatus.UnderInvestigation, StatusUnderInvestigation)
	}
	return doc, nil
}

type csafProduct struct {
	ProductID             string `json:"product_id"`
	Name                  string `json:"name"`
	ProductIdentification struct {
		Purl string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

func collectCSAFProducts(products []csafProduct, out map[string]string) {
	for _, p := range products {
		if p.ProductID == "" {
			continue
		}
		if purl := p.ProductIdentification.Purl; purl != "" {
			out[p.ProductID] = purl
		} else if _, seen := out[p.ProductID]; !seen {
			out[p.ProductID] = ""
		}
	}
}

// collectCSAFBranches walks the product tree, which nests arbitrarily deep.
func collectCSAFBranches(branches []csafBranch, out map[string]string) {
	for _, b := range branches {
		if b.Product != nil {
			collectCSAFProducts([]csafProduct{*b.Product}, out)
		}
		collectCSAFBranches(b.Branches, out)
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

// parseTime accepts the timestamp spellings these formats use in practice.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// firstTime returns the first non-zero time.
func firstTime(times ...time.Time) time.Time {
	for _, t := range times {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
