// Package schema provides CycloneDX BOM validation against embedded JSON schemas.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed *.schema.json
var schemaFS embed.FS

// validVersions lists supported CDX spec versions from highest to lowest.
// ValidateCDX honors the document's declared specVersion when present.
var validVersions = []string{"1.7", "1.6", "1.5", "1.4", "1.3", "1.2"}

type ValidationViolation struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// compiled caches compiled schemas so repeated validations are fast.
var (
	compiled    map[string]*jsonschema.Schema
	compileErr  error
	compileOnce sync.Once
)

func ensureCompiled() error {
	compileOnce.Do(func() {
		compiled = make(map[string]*jsonschema.Schema, len(validVersions))

		// Shared resources referenced via $ref from the BOM schemas.
		sharedFiles := []struct {
			file string
			id   string
		}{
			{"spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"},
			{"jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"},
			{"cryptography-defs.schema.json", "http://cyclonedx.org/schema/cryptography-defs.schema.json"},
		}

		for _, v := range validVersions {
			c := jsonschema.NewCompiler()

			// Register shared schemas so $ref resolves without network.
			for _, sf := range sharedFiles {
				data, err := schemaFS.ReadFile(sf.file)
				if err != nil {
					compileErr = fmt.Errorf("read %s: %w", sf.file, err)
					return
				}
				doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
				if err != nil {
					compileErr = fmt.Errorf("unmarshal %s: %w", sf.file, err)
					return
				}
				if err := c.AddResource(sf.id, doc); err != nil {
					compileErr = fmt.Errorf("add resource %s: %w", sf.id, err)
					return
				}
			}

			// Register and compile the BOM schema for this version.
			bomFile := fmt.Sprintf("bom-%s.schema.json", v)
			bomID := fmt.Sprintf("http://cyclonedx.org/schema/bom-%s.schema.json", v)

			data, err := schemaFS.ReadFile(bomFile)
			if err != nil {
				compileErr = fmt.Errorf("read %s: %w", bomFile, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
			if err != nil {
				compileErr = fmt.Errorf("unmarshal %s: %w", bomFile, err)
				return
			}
			if err := c.AddResource(bomID, doc); err != nil {
				compileErr = fmt.Errorf("add resource %s: %w", bomID, err)
				return
			}

			sch, err := c.Compile(bomID)
			if err != nil {
				compileErr = fmt.Errorf("compile %s: %w", bomFile, err)
				return
			}
			compiled[v] = sch
		}
	})
	return compileErr
}

// ValidateCycloneDX validates raw CycloneDX JSON against the schema declared
// by bom.specVersion. It mirrors the website upload validator: non-CycloneDX
// JSON returns specVersion="" with no violations, schema failures return a
// bounded path/message list, and malformed JSON is fatal.
func ValidateCycloneDX(data []byte) (string, []ValidationViolation, error) {
	if err := ensureCompiled(); err != nil {
		return "", nil, fmt.Errorf("schema init: %w", err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var header struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if !strings.EqualFold(header.BomFormat, "CycloneDX") || header.SpecVersion == "" {
		return "", nil, nil
	}

	sch, ok := compiled[header.SpecVersion]
	if !ok {
		return header.SpecVersion, []ValidationViolation{{
			Path:    "/specVersion",
			Message: fmt.Sprintf("unsupported CycloneDX version %q (supported: %s)", header.SpecVersion, strings.Join(SupportedVersionsAscending(), ", ")),
		}}, nil
	}
	if err := sch.Validate(doc); err != nil {
		return header.SpecVersion, flattenValidationErrors(err), nil
	}
	return header.SpecVersion, nil, nil
}

// ValidateCDX validates raw CycloneDX JSON against embedded schemas.
func ValidateCDX(data []byte) (string, error) {
	version, violations, err := ValidateCycloneDX(data)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", fmt.Errorf("not a CycloneDX BOM")
	}
	if len(violations) > 0 {
		return "", fmt.Errorf("CDX document does not validate against declared specVersion %s: %s", version, violations[0].Message)
	}
	return version, nil
}

// SupportedVersions returns the list of CDX spec versions supported for validation.
func SupportedVersions() []string {
	out := make([]string, len(validVersions))
	copy(out, validVersions)
	return out
}

func SupportedVersionsAscending() []string {
	out := SupportedVersions()
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func flattenValidationErrors(err error) []ValidationViolation {
	const cap = 25
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []ValidationViolation{{Path: "", Message: err.Error()}}
	}
	var out []ValidationViolation
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(out) >= cap {
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
	if len(out) == cap {
		out = append(out, ValidationViolation{Path: "", Message: fmt.Sprintf("...additional violations truncated (first %d shown)", cap)})
	}
	return out
}
