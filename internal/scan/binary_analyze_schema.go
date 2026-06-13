package scan

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// binaryAnalyzeSchema is the JSON Schema (draft-07) the CLI validates its
// /v2/cli.analyze request against before sending — the symmetric counterpart
// to the server-side container-binary-analyze.schema.json.
//
//go:embed binary_analyze.schema.json
var binaryAnalyzeSchema []byte

var (
	binSchema    *jsonschema.Schema
	binSchemaErr error
	binSchemaMu  sync.Once
)

func compiledBinarySchema() (*jsonschema.Schema, error) {
	binSchemaMu.Do(func() {
		var doc any
		if err := json.Unmarshal(binaryAnalyzeSchema, &doc); err != nil {
			binSchemaErr = fmt.Errorf("schema parse: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		const url = "internal:///binary-analyze.schema.json"
		if err := c.AddResource(url, doc); err != nil {
			binSchemaErr = fmt.Errorf("add resource: %w", err)
			return
		}
		s, err := c.Compile(url)
		if err != nil {
			binSchemaErr = fmt.Errorf("compile: %w", err)
			return
		}
		binSchema = s
	})
	return binSchema, binSchemaErr
}

// ValidateAnalyzeRequest validates a marshalled /v2/cli.analyze request body
// against the embedded JSON schema. A nil error means the body is well-formed;
// a non-nil error describes the first schema violations. A schema-compile
// failure (packaging bug) is returned as an error too, so callers can decide
// whether to proceed.
func ValidateAnalyzeRequest(body []byte) error {
	s, err := compiledBinarySchema()
	if err != nil {
		return err
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if verr := s.Validate(doc); verr != nil {
		return fmt.Errorf("schema validation failed: %s", summariseSchemaError(verr))
	}
	return nil
}

// summariseSchemaError flattens a jsonschema validation error tree into a
// short, single-line summary (leaf instance locations + messages, capped).
func summariseSchemaError(verr error) string {
	ve, ok := verr.(*jsonschema.ValidationError)
	if !ok {
		return verr.Error()
	}
	const cap = 8
	var msgs []string
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(msgs) >= cap {
			return
		}
		if len(e.Causes) == 0 {
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			msgs = append(msgs, loc+": "+e.Error())
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return strings.Join(msgs, "; ")
}
