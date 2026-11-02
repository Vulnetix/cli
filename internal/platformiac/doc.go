// Package platformiac decides what is a Platform IaC document and finds them.
//
// The rule, in one place: a document is Platform IaC if and only if its
// apiVersion is vulnetix.com/v1 and its kind is one config-schemas knows. A
// kind whose schema carries x-vulnetix.validateOnly is validated here and never
// sent to the config engine. Everything else under .vulnetix/ (SARIF,
// CycloneDX, OpenVEX, memory, credentials) is not, and is skipped where it sits
// in a folder.
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
	"fmt"
	"sort"
	"strings"
	"sync"

	configschemas "github.com/vulnetix/config-schemas"
)

// APIVersion is the only apiVersion a document has.
const APIVersion = "vulnetix.com/v1"

// Kinds lists every kind config-schemas releases, sorted.
func Kinds() []string {
	out := append([]string(nil), configschemas.Kinds()...)
	sort.Strings(out)
	return out
}

// IsKnownKind reports whether kind is a Platform IaC kind.
func IsKnownKind(kind string) bool {
	for _, k := range configschemas.Kinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// IsLocal reports whether kind is validated here and never sent to the config
// engine: its schema carries x-vulnetix.validateOnly, because nothing on the
// server stores it yet.
func IsLocal(kind string) bool {
	m, err := configschemas.KindMeta(kind)
	return err == nil && m.ValidateOnly
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

// Validator checks a document against its kind's schema.
type Validator struct {
	shared *configschemas.Validator
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
		validator = &Validator{shared: shared}
	})
	return validator, validatorErr
}

// Validate checks one document.
func (v *Validator) Validate(d configschemas.Document) error {
	if d.Kind != "" && !IsKnownKind(d.Kind) {
		return fmt.Errorf("unknown kind %q (known: %s)", d.Kind, strings.Join(Kinds(), ", "))
	}
	return v.shared.Validate(d)
}
