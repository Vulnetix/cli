// Package schema provides CycloneDX BOM validation against embedded JSON schemas.
package schema

import (
	"bytes"
	"embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed *.schema.json
var schemaFS embed.FS

// validVersions lists supported CDX spec versions from highest to lowest.
// ValidateCDX tries each in order and short-circuits on the first match.
var validVersions = []string{"1.7", "1.6", "1.5", "1.4"}

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

// ValidateCDX validates raw CycloneDX JSON against embedded schemas.
// It tries versions from highest (1.7) to lowest (1.4) and returns the
// first version that validates successfully (short-circuit).
func ValidateCDX(data []byte) (string, error) {
	if err := ensureCompiled(); err != nil {
		return "", fmt.Errorf("schema init: %w", err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	for _, v := range validVersions {
		sch := compiled[v]
		if err := sch.Validate(doc); err == nil {
			return v, nil
		}
	}

	return "", fmt.Errorf("CDX document does not validate against any supported schema (1.4–1.7)")
}

// SupportedVersions returns the list of CDX spec versions supported for validation.
func SupportedVersions() []string {
	out := make([]string, len(validVersions))
	copy(out, validVersions)
	return out
}
