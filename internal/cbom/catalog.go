// Package cbom discovers cryptographic usage in a codebase — in source, config,
// certificates/keys on disk and declared crypto libraries — and maps it to a
// CycloneDX Cryptography Bill of Materials, classifying each algorithm for
// post-quantum posture (quantum-safe | quantum-vulnerable | deprecated | hybrid).
//
// All detection is driven by a declarative catalog (internal/cbom/catalog/*.json)
// so the rules — algorithm aliases, per-language source patterns, config patterns,
// crypto-library imports and the per-country approval matrix — can be maintained
// without code changes. The catalog is embedded in the binary and can be extended
// or overridden at runtime with --catalog.
package cbom

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

//go:embed catalog/*.json
var catalogFS embed.FS

// AlgorithmDef describes one cryptographic algorithm: how to detect it, its
// canonical SPDX identity, its CycloneDX algorithmProperties and its PQC posture.
type AlgorithmDef struct {
	ID                     string              `json:"id"`   // canonical SPDX id (override key)
	Name                   string              `json:"name"` // canonical stored name
	SPDXClass              string              `json:"spdx_class,omitempty"`
	OID                    string              `json:"oid,omitempty"`
	Aliases                []string            `json:"aliases,omitempty"`
	Primitive              string              `json:"primitive,omitempty"` // CycloneDX primitive enum
	ParameterSet           string              `json:"parameter_set,omitempty"`
	Curve                  string              `json:"curve,omitempty"`
	Mode                   string              `json:"mode,omitempty"`    // CycloneDX mode enum
	Padding                string              `json:"padding,omitempty"` // CycloneDX padding enum
	CryptoFunctions        []string            `json:"crypto_functions,omitempty"`
	ClassicalSecurityLevel int                 `json:"classical_security_level,omitempty"`
	NISTQuantumLevel       int                 `json:"nist_quantum_security_level,omitempty"`
	PQCStatus              string              `json:"pqc_status,omitempty"`
	Standards              map[string]string   `json:"standards,omitempty"`
	SourcePatterns         map[string][]string `json:"source_patterns,omitempty"` // language -> patterns
	ConfigPatterns         []string            `json:"config_patterns,omitempty"`
}

// ExtractorDef captures an algorithm token from a generic crypto-API call. The
// captured token is normalized and looked up in the alias index, so arbitrary
// case/separator variants (sha256, SHA-256, SHA_256, …) resolve to one algorithm.
type ExtractorDef struct {
	Languages []string `json:"languages,omitempty"` // empty = any file
	Pattern   string   `json:"pattern"`             // one capture group = the token
	Role      string   `json:"role,omitempty"`      // algorithm | transform | jwt
}

// LibraryDef describes a cryptographic library / SDK.
type LibraryDef struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Provider       string            `json:"provider,omitempty"`
	Languages      []string          `json:"languages,omitempty"`
	PurlNames      map[string]string `json:"purl_names,omitempty"`
	ImportPatterns []string          `json:"import_patterns,omitempty"`
}

// Catalog is the raw (uncompiled) detection catalog.
type Catalog struct {
	Version    string         `json:"version"`
	Extractors []ExtractorDef `json:"call_extractors,omitempty"`
	Algorithms []AlgorithmDef `json:"algorithms"`
	Libraries  []LibraryDef   `json:"libraries"`
}

// ---- compiled forms ------------------------------------------------------

// CompiledCatalog is the catalog with all regexes compiled and the alias index
// built. It is the single matching surface used by every detection pass.
type CompiledCatalog struct {
	Version    string
	Algorithms []CompiledAlgorithm
	Libraries  []CompiledLibrary
	Extractors []CompiledExtractor
	// aliasIndex maps a normalized alias/name/id to an index into Algorithms.
	aliasIndex map[string]int
}

type CompiledAlgorithm struct {
	Def    AlgorithmDef
	Source map[string][]*regexp.Regexp // canonical language -> patterns
	Config []*regexp.Regexp
}

type CompiledLibrary struct {
	Def     LibraryDef
	Imports []*regexp.Regexp
}

type CompiledExtractor struct {
	Languages map[string]bool
	Re        *regexp.Regexp
	Role      string
}

// DefaultCatalog loads and merges the embedded catalog/*.json files.
func DefaultCatalog() (*Catalog, error) {
	entries, err := catalogFS.ReadDir("catalog")
	if err != nil {
		return nil, err
	}
	cat := &Catalog{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := catalogFS.ReadFile("catalog/" + e.Name())
		if err != nil {
			return nil, err
		}
		var part Catalog
		if err := json.Unmarshal(data, &part); err != nil {
			return nil, fmt.Errorf("catalog/%s: %w", e.Name(), err)
		}
		mergeCatalog(cat, &part)
	}
	return cat, nil
}

// LoadCatalog loads the builtin catalog (unless noBuiltin) and merges an optional
// override file on top (upsert by id).
func LoadCatalog(overridePath string, noBuiltin bool) (*Catalog, error) {
	cat := &Catalog{}
	if !noBuiltin {
		def, err := DefaultCatalog()
		if err != nil {
			return nil, err
		}
		cat = def
	}
	if overridePath != "" {
		data, err := os.ReadFile(overridePath)
		if err != nil {
			return nil, fmt.Errorf("reading catalog %s: %w", overridePath, err)
		}
		var override Catalog
		if err := json.Unmarshal(data, &override); err != nil {
			return nil, fmt.Errorf("parsing catalog %s: %w", overridePath, err)
		}
		mergeCatalog(cat, &override)
	}
	if cat.Version == "" {
		cat.Version = "custom"
	}
	return cat, nil
}

// mergeCatalog upserts src into dst by id (algorithms, libraries) and appends
// extractors. A non-empty src.Version wins.
func mergeCatalog(dst, src *Catalog) {
	if src.Version != "" {
		dst.Version = src.Version
	}
	dst.Extractors = append(dst.Extractors, src.Extractors...)
	algoIdx := map[string]int{}
	for i, a := range dst.Algorithms {
		algoIdx[a.ID] = i
	}
	for _, a := range src.Algorithms {
		if i, ok := algoIdx[a.ID]; ok {
			dst.Algorithms[i] = a
		} else {
			algoIdx[a.ID] = len(dst.Algorithms)
			dst.Algorithms = append(dst.Algorithms, a)
		}
	}
	libIdx := map[string]int{}
	for i, l := range dst.Libraries {
		libIdx[l.ID] = i
	}
	for _, l := range src.Libraries {
		if i, ok := libIdx[l.ID]; ok {
			dst.Libraries[i] = l
		} else {
			libIdx[l.ID] = len(dst.Libraries)
			dst.Libraries = append(dst.Libraries, l)
		}
	}
}

// CycloneDX algorithmProperties enum value sets, validated at catalog-compile
// time so a bad catalog fails `just gen-cbom` rather than only at BuildCBOM.
var (
	validPrimitives = set("drbg", "mac", "block-cipher", "stream-cipher", "signature",
		"hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown")
	validCryptoFunctions = set("generate", "keygen", "encrypt", "decrypt", "digest", "tag",
		"keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown")
	validModes    = set("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown")
	validPaddings = set("pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown")
	validPQC      = set("quantum-safe", "quantum-vulnerable", "deprecated", "hybrid")
)

func set(vs ...string) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[v] = true
	}
	return m
}

// Compile validates and compiles every pattern and builds the alias index. It is
// the single validation gate: an invalid regex, duplicate id, or out-of-enum
// CycloneDX value fails here.
func (c *Catalog) Compile() (*CompiledCatalog, error) {
	out := &CompiledCatalog{Version: c.Version, aliasIndex: map[string]int{}}

	seen := map[string]bool{}
	for i := range c.Algorithms {
		a := c.Algorithms[i]
		if a.ID == "" || a.Name == "" {
			return nil, fmt.Errorf("algorithm %d: id and name are required", i)
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("duplicate algorithm id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Primitive != "" && !validPrimitives[a.Primitive] {
			return nil, fmt.Errorf("algorithm %q: invalid primitive %q", a.ID, a.Primitive)
		}
		for _, f := range a.CryptoFunctions {
			if !validCryptoFunctions[f] {
				return nil, fmt.Errorf("algorithm %q: invalid crypto_function %q", a.ID, f)
			}
		}
		if a.Mode != "" && !validModes[a.Mode] {
			return nil, fmt.Errorf("algorithm %q: invalid mode %q", a.ID, a.Mode)
		}
		if a.Padding != "" && !validPaddings[a.Padding] {
			return nil, fmt.Errorf("algorithm %q: invalid padding %q", a.ID, a.Padding)
		}
		if a.PQCStatus != "" && !validPQC[a.PQCStatus] {
			return nil, fmt.Errorf("algorithm %q: invalid pqc_status %q", a.ID, a.PQCStatus)
		}
		if a.NISTQuantumLevel < 0 || a.NISTQuantumLevel > 6 {
			return nil, fmt.Errorf("algorithm %q: nist_quantum_security_level must be 0..6", a.ID)
		}

		ca := CompiledAlgorithm{Def: a, Source: map[string][]*regexp.Regexp{}}
		for lang, pats := range a.SourcePatterns {
			canon := canonicalLang(lang)
			for _, p := range pats {
				re, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("algorithm %q source[%s]: %w", a.ID, lang, err)
				}
				ca.Source[canon] = append(ca.Source[canon], re)
			}
		}
		for _, p := range a.ConfigPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("algorithm %q config: %w", a.ID, err)
			}
			ca.Config = append(ca.Config, re)
		}
		idx := len(out.Algorithms)
		out.Algorithms = append(out.Algorithms, ca)

		// Index id, name and aliases (normalized) → algorithm. First writer wins
		// so a more specific PQC entry isn't shadowed by a generic alias clash.
		for _, key := range append([]string{a.ID, a.Name}, a.Aliases...) {
			n := Normalize(key)
			if n == "" {
				continue
			}
			if _, exists := out.aliasIndex[n]; !exists {
				out.aliasIndex[n] = idx
			}
		}
	}

	for i := range c.Libraries {
		l := c.Libraries[i]
		cl := CompiledLibrary{Def: l}
		for _, p := range l.ImportPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("library %q import: %w", l.ID, err)
			}
			cl.Imports = append(cl.Imports, re)
		}
		out.Libraries = append(out.Libraries, cl)
	}

	for i, e := range c.Extractors {
		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			return nil, fmt.Errorf("call_extractor %d: %w", i, err)
		}
		if re.NumSubexp() < 1 {
			return nil, fmt.Errorf("call_extractor %d: pattern must have one capture group", i)
		}
		ce := CompiledExtractor{Re: re, Role: e.Role}
		if len(e.Languages) > 0 {
			ce.Languages = map[string]bool{}
			for _, l := range e.Languages {
				ce.Languages[canonicalLang(l)] = true
			}
		}
		out.Extractors = append(out.Extractors, ce)
	}

	return out, nil
}

// Lookup resolves a raw token (e.g. "SHA256", "Sha256", "SHA_256") to its
// canonical algorithm via the normalized alias index. This is what makes
// case/separator variants equivalent for detection.
func (c *CompiledCatalog) Lookup(token string) (*CompiledAlgorithm, bool) {
	n := Normalize(token)
	if n == "" {
		return nil, false
	}
	if i, ok := c.aliasIndex[n]; ok {
		return &c.Algorithms[i], true
	}
	return nil, false
}
