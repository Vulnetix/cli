package cyclonedx

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.schema.json
var schemaFS embed.FS

var supportedSpecVersions = map[string]string{
	"1.2": "schemas/bom-1.2.schema.json",
	"1.3": "schemas/bom-1.3.schema.json",
	"1.4": "schemas/bom-1.4.schema.json",
	"1.5": "schemas/bom-1.5.schema.json",
	"1.6": "schemas/bom-1.6.schema.json",
	"1.7": "schemas/bom-1.7.schema.json",
	"2.0": "schemas/bom-2.0.schema.json",
}

var (
	schemaCacheMu sync.Mutex
	schemaCache   = map[string]*jsonschema.Schema{}
)

type CDXOrg struct {
	Name string `json:"name"`
}

type CDXComponent struct {
	BomRef       string  `json:"bom-ref"`
	Type         string  `json:"type"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Purl         string  `json:"purl"`
	Cpe          string  `json:"cpe"`
	Group        string  `json:"group"`
	Scope        string  `json:"scope"`
	Author       string  `json:"author"`
	Publisher    string  `json:"publisher"`
	Description  string  `json:"description"`
	Manufacturer *CDXOrg `json:"manufacturer"`
	Supplier     *CDXOrg `json:"supplier"`
	Hashes       []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
	ExternalReferences []struct {
		URL  string `json:"url"`
		Type string `json:"type"`
	} `json:"externalReferences"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Licenses []struct {
		License struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
	} `json:"licenses"`
}

type CDXVulnRating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Method   string  `json:"method"`
	Vector   string  `json:"vector"`
}

type CDXVulnerability struct {
	BomRef string `json:"bom-ref"`
	ID     string `json:"id"`
	Source *struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"source"`
	Ratings        []CDXVulnRating `json:"ratings"`
	CWEs           []int           `json:"cwes"`
	Description    string          `json:"description"`
	Recommendation string          `json:"recommendation"`
	Published      string          `json:"published"`
	Updated        string          `json:"updated"`
	Affects        []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type CDXMetadata struct {
	Timestamp    string        `json:"timestamp"`
	Component    *CDXComponent `json:"component"`
	Manufacture  *CDXOrg       `json:"manufacture"`
	Manufacturer *CDXOrg       `json:"manufacturer"`
	Supplier     *CDXOrg       `json:"supplier"`
	Authors      []struct {
		Name string `json:"name"`
	} `json:"authors"`
	Tools *CDXTools `json:"tools"`
}

// CDXTools models metadata.tools, whose shape changed across CycloneDX versions:
//   - 1.2–1.4: an array of tool objects, e.g. [{"vendor","name","version","hashes"}]
//   - 1.5+:    an object, e.g. {"components":[...], "services":[...]}
//
// We accept both and tolerate anything else. Tool metadata is ancillary,
// best-effort enrichment (see ExtractToolMeta), so a malformed or unexpected
// tools shape must never fail the whole BOM ingestion — UnmarshalJSON only ever
// returns nil, leaving Components empty when it can't make sense of the input.
type CDXTools struct {
	Components []CDXComponent `json:"components"`
}

func (t *CDXTools) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		// Legacy array form. Decode into CDXComponent directly so name/version/
		// hashes map for free, then backfill the legacy "vendor" into Publisher
		// (CDXComponent has no vendor field) where extractToolMeta looks for it.
		var comps []CDXComponent
		if err := json.Unmarshal(trimmed, &comps); err != nil {
			return nil
		}
		var vendors []struct {
			Vendor string `json:"vendor"`
		}
		_ = json.Unmarshal(trimmed, &vendors)
		for i := range comps {
			if comps[i].Type == "" {
				comps[i].Type = "application"
			}
			if i < len(vendors) && comps[i].Publisher == "" {
				comps[i].Publisher = vendors[i].Vendor
			}
		}
		t.Components = comps
	case '{':
		var obj struct {
			Components []CDXComponent `json:"components"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil
		}
		t.Components = obj.Components
	}
	return nil
}

// CDXDependency represents one entry in the top-level "dependencies" array.
// CycloneDX 1.4+ uses "dependsOn"; 1.2–1.3 used "dependencies" for the same
// nested list. We decode both and coalesce into DependsOn so all downstream
// code can use a single field name.
type CDXDependency struct {
	Ref       string   `json:"-"`
	DependsOn []string `json:"-"`
}

func (d *CDXDependency) UnmarshalJSON(b []byte) error {
	var raw struct {
		Ref          string   `json:"ref"`
		DependsOn    []string `json:"dependsOn"`    // CycloneDX 1.4+
		Dependencies []string `json:"dependencies"` // CycloneDX 1.2–1.3
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	d.Ref = raw.Ref
	d.DependsOn = raw.DependsOn
	// Fall back to the legacy field when the modern one is absent.
	if len(d.DependsOn) == 0 && len(raw.Dependencies) > 0 {
		d.DependsOn = raw.Dependencies
	}
	return nil
}

type CDXBom struct {
	BomFormat       string             `json:"bomFormat"`
	SpecFormat      string             `json:"specFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Metadata        CDXMetadata        `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Dependencies    []CDXDependency    `json:"dependencies"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities"`
}

func ParseCDX(data []byte) (*CDXBom, error) {
	if err := ValidateCDX(data); err != nil {
		return nil, err
	}
	var bom CDXBom
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}
	if bom.BomFormat == "" && bom.SpecFormat == "CycloneDX" {
		bom.BomFormat = bom.SpecFormat
	}
	return &bom, nil
}

func DetectSpecVersion(data []byte) (string, error) {
	var header struct {
		BomFormat   string `json:"bomFormat"`
		SpecFormat  string `json:"specFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", err
	}
	format := header.BomFormat
	if format == "" {
		format = header.SpecFormat
	}
	if format != "CycloneDX" {
		return "", fmt.Errorf("unsupported CycloneDX format %q", format)
	}
	if header.SpecVersion == "" {
		return "", fmt.Errorf("missing specVersion")
	}
	if _, ok := supportedSpecVersions[header.SpecVersion]; !ok {
		return "", fmt.Errorf("unsupported CycloneDX specVersion %q", header.SpecVersion)
	}
	return header.SpecVersion, nil
}

func ValidateCDX(data []byte) error {
	version, err := DetectSpecVersion(data)
	if err != nil {
		return err
	}
	schema, err := schemaForVersion(version)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("CycloneDX %s schema validation failed: %w", version, err)
	}
	return nil
}

func schemaForVersion(version string) (*jsonschema.Schema, error) {
	schemaCacheMu.Lock()
	defer schemaCacheMu.Unlock()
	if schemaCache[version] != nil {
		return schemaCache[version], nil
	}
	path, ok := supportedSpecVersions[version]
	if !ok {
		return nil, fmt.Errorf("unsupported CycloneDX specVersion %q", version)
	}
	compiler := jsonschema.NewCompiler()
	entries, err := fs.ReadDir(schemaFS, "schemas")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := "schemas/" + entry.Name()
		b, err := schemaFS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		if err := compiler.AddResource(name, doc); err != nil {
			return nil, err
		}
		if err := compiler.AddResource(entry.Name(), doc); err != nil {
			return nil, err
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+entry.Name(), doc); err != nil {
			return nil, err
		}
		if err := compiler.AddResource("https://cyclonedx.org/schema/"+entry.Name(), doc); err != nil {
			return nil, err
		}
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		return nil, err
	}
	schemaCache[version] = schema
	return schema, nil
}

// ExtractEcosystem parses the ecosystem from a PURL (pkg:<type>/...) or returns "".
func ExtractEcosystem(purl string) string {
	// pkg:npm/lodash@4.17.0 → "npm"
	rest := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(rest, "/"); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// ExtractLicense returns the first license identifier from a component.
func ExtractLicense(comp CDXComponent) string {
	for _, l := range comp.Licenses {
		if l.License.ID != "" {
			return l.License.ID
		}
		if l.License.Name != "" {
			return l.License.Name
		}
	}
	return ""
}
