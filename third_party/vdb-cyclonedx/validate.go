package cyclonedx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// supportedVersionsAsc lists supported CDX spec versions low-to-high. It is the
// display/order companion to the supportedSpecVersions map (which only carries
// version→schema-path). Keep both in sync.
var supportedVersionsAsc = []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "2.0"}

// ValidationViolation is a single schema-validation failure with a JSON Pointer
// path into the instance and a human-readable message.
type ValidationViolation struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// SupportedVersions returns supported CDX spec versions, highest first.
func SupportedVersions() []string {
	out := make([]string, len(supportedVersionsAsc))
	for i, v := range supportedVersionsAsc {
		out[len(supportedVersionsAsc)-1-i] = v
	}
	return out
}

// SupportedVersionsAscending returns supported CDX spec versions, lowest first.
func SupportedVersionsAscending() []string {
	out := make([]string, len(supportedVersionsAsc))
	copy(out, supportedVersionsAsc)
	return out
}

// ValidateCycloneDX validates raw CycloneDX JSON against the schema declared by
// the document's specVersion and returns a bounded list of violations rather
// than a single wrapped error. It is the shared implementation behind the CLI
// and website upload validators:
//
//   - Non-CycloneDX JSON (bomFormat != "cyclonedx" or no specVersion) returns
//     version="" with no violations — the caller decides whether to allow other
//     formats.
//   - An unsupported but declared CycloneDX version returns that version with a
//     single /specVersion violation.
//   - Schema failures return the declared version and a bounded path/message
//     list (first 25 leaf errors).
//   - Malformed JSON is a fatal error.
func ValidateCycloneDX(data []byte) (string, []ValidationViolation, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var header struct {
		BomFormat   string `json:"bomFormat"`
		SpecFormat  string `json:"specFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
	}

	format := header.BomFormat
	if format == "" {
		format = header.SpecFormat
	}
	if !strings.EqualFold(format, "CycloneDX") || header.SpecVersion == "" {
		return "", nil, nil
	}

	if _, ok := supportedSpecVersions[header.SpecVersion]; !ok {
		return header.SpecVersion, []ValidationViolation{{
			Path:    "/specVersion",
			Message: fmt.Sprintf("unsupported CycloneDX version %q (supported: %s)", header.SpecVersion, strings.Join(SupportedVersionsAscending(), ", ")),
		}}, nil
	}

	sch, err := schemaForVersion(header.SpecVersion)
	if err != nil {
		return header.SpecVersion, nil, fmt.Errorf("schema init for %s: %w", header.SpecVersion, err)
	}
	if err := sch.Validate(doc); err != nil {
		return header.SpecVersion, flattenValidationErrors(err), nil
	}
	return header.SpecVersion, nil, nil
}

// flattenValidationErrors walks a jsonschema.ValidationError tree into a bounded
// list of leaf violations, each with a JSON Pointer path into the instance.
func flattenValidationErrors(err error) []ValidationViolation {
	const max = 25
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []ValidationViolation{{Path: "", Message: err.Error()}}
	}
	var out []ValidationViolation
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(out) >= max {
			return
		}
		if len(e.Causes) == 0 {
			path := "/" + strings.Join(e.InstanceLocation, "/")
			out = append(out, ValidationViolation{Path: path, Message: e.Error()})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	if len(out) == max {
		out = append(out, ValidationViolation{Path: "", Message: fmt.Sprintf("...additional violations truncated (first %d shown)", max)})
	}
	return out
}
