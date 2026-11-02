// Package platformiac decides what is a Platform IaC document and finds them.
//
// The rule, in one place: a document is Platform IaC if and only if its
// apiVersion is vulnetix.com/v1 and its kind is one config-schemas knows, or a
// LocalKind this CLI validates itself. Everything else that lives under
// .vulnetix/ (SARIF, CycloneDX, OpenVEX, memory, credentials) is not, and is
// skipped where it sits in a folder.
//
//	| Case                                                      | Result                     |
//	|-----------------------------------------------------------|----------------------------|
//	| A folder file with no vulnetix.com/v1 content              | skipped; a note with -v    |
//	| A vulnetix.com/v1 document whose kind is unknown           | error                      |
//	| A file that mixes documents with other content             | error                      |
//	| A well-known file holding the wrong kind                   | error                      |
//	| A file named with -f that is not a document                | error                      |
package platformiac

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	configschemas "github.com/vulnetix/config-schemas"
)

// APIVersion is the only apiVersion a document has.
const APIVersion = "vulnetix.com/v1"

//go:embed schemas/LicenseExceptions.schema.json
var licenseExceptionsSchema []byte

// LocalKinds are kinds the CLI validates with a schema of its own and never
// sends to the config engine. LicenseExceptions is one until config-schemas
// releases it (switch to that copy then) and vdb-site has an adapter for it.
var LocalKinds = map[string][]byte{
	"LicenseExceptions": licenseExceptionsSchema,
}

// Kinds lists every kind: config-schemas' and the local ones, sorted.
func Kinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range configschemas.Kinds() {
		seen[k] = true
		out = append(out, k)
	}
	for k := range LocalKinds {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// IsKnownKind reports whether kind is a Platform IaC kind.
func IsKnownKind(kind string) bool {
	if _, ok := LocalKinds[kind]; ok {
		return true
	}
	for _, k := range configschemas.Kinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// IsLocal reports whether kind is validated here and never sent.
func IsLocal(kind string) bool {
	_, ok := LocalKinds[kind]
	return ok
}

// Class is what a decoded value is.
type Class int

const (
	// NotDocument has no vulnetix.com/v1 apiVersion.
	NotDocument Class = iota
	// IsDoc is a vulnetix.com/v1 document of a known kind.
	IsDoc
	// UnknownKind is a vulnetix.com/v1 document of a kind nobody knows.
	UnknownKind
)

// Classify sorts one decoded value.
func Classify(v any) (Class, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return NotDocument, ""
	}
	if api, _ := m["apiVersion"].(string); api != APIVersion {
		return NotDocument, ""
	}
	kind, _ := m["kind"].(string)
	if !IsKnownKind(kind) {
		return UnknownKind, kind
	}
	return IsDoc, kind
}

// IsDocument reports whether v is a Platform IaC document.
func IsDocument(v any) bool {
	c, _ := Classify(v)
	return c == IsDoc
}

// Validator checks a document against its kind's schema, local or not.
type Validator struct {
	shared *configschemas.Validator
	local  map[string]*jsonschema.Schema
}

var (
	validatorOnce sync.Once
	validator     *Validator
	validatorErr  error
)

// NewValidator compiles every schema once.
func NewValidator() (*Validator, error) {
	validatorOnce.Do(func() {
		shared, err := configschemas.NewValidator()
		if err != nil {
			validatorErr = err
			return
		}
		v := &Validator{shared: shared, local: map[string]*jsonschema.Schema{}}
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		c.AssertFormat()
		for kind, raw := range LocalKinds {
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				validatorErr = fmt.Errorf("%s schema: %w", kind, err)
				return
			}
			url := "local://" + kind + ".schema.json"
			if err := c.AddResource(url, doc); err != nil {
				validatorErr = err
				return
			}
			s, err := c.Compile(url)
			if err != nil {
				validatorErr = fmt.Errorf("%s schema: %w", kind, err)
				return
			}
			v.local[kind] = s
		}
		validator = v
	})
	return validator, validatorErr
}

// Validate checks one document.
func (v *Validator) Validate(d configschemas.Document) error {
	if s, ok := v.local[d.Kind]; ok {
		return s.Validate(d.Value)
	}
	if d.Kind != "" && !IsKnownKind(d.Kind) {
		return fmt.Errorf("unknown kind %q (known: %s)", d.Kind, strings.Join(Kinds(), ", "))
	}
	return v.shared.Validate(d)
}
