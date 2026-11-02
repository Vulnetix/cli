// Command cbomgen renders the CBOM detection documentation from the single
// source of truth: the embedded catalog (internal/cbom/catalog/*.json).
//
// It validates the catalog (every regex compiles, every CycloneDX enum value is
// in range) and then writes:
//   - docs/generated/cbom/algorithms.md
//   - docs/generated/cbom/standards-matrix.md
//   - docs/generated/cbom/catalog-format.md
//
// These pages are not published from this repository. The platform docs
// (docs.vulnetix.com, Vulnetix/platform-docs) copy them from a cli checkout with
// migration/generators/sbom-catalog-pages.py, so they must stay committed.
//
// Docs therefore can never drift from the detection rules. Run via:
//
//	just gen-cbom        # go run ./internal/cbom/cbomgen
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cbom"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fail(err)
	}
	cat, err := cbom.LoadCatalog("", false)
	if err != nil {
		fail(err)
	}
	if _, err := cat.Compile(); err != nil {
		fail(fmt.Errorf("catalog failed validation: %w", err))
	}

	docs := filepath.Join(root, "docs", "generated")
	writes := map[string]string{
		filepath.Join(docs, "cbom", "algorithms.md"):       algorithmsMD(cat),
		filepath.Join(docs, "cbom", "standards-matrix.md"): standardsMD(cat),
		filepath.Join(docs, "cbom", "catalog-format.md"):   formatMD(),
	}
	for path, body := range writes {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			fail(err)
		}
	}

	var vuln, safe, dep, hybrid int
	for _, a := range cat.Algorithms {
		switch a.PQCStatus {
		case "quantum-vulnerable":
			vuln++
		case "quantum-safe":
			safe++
		case "deprecated":
			dep++
		case "hybrid":
			hybrid++
		}
	}
	fmt.Printf("cbomgen: catalog %s — %d algorithms (%d quantum-vulnerable, %d deprecated, %d hybrid, %d quantum-safe), %d libraries\n",
		cat.Version, len(cat.Algorithms), vuln, dep, hybrid, safe, len(cat.Libraries))
	fmt.Printf("cbomgen: wrote %d docs under %s\n", len(writes), docs)
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cbomgen:", err)
	os.Exit(1)
}

// ---- markdown builders ---------------------------------------------------

func algorithmsMD(cat *cbom.Catalog) string {
	algos := append([]cbom.AlgorithmDef(nil), cat.Algorithms...)
	sort.Slice(algos, func(i, j int) bool {
		if algos[i].PQCStatus != algos[j].PQCStatus {
			return algos[i].PQCStatus < algos[j].PQCStatus
		}
		return algos[i].Name < algos[j].Name
	})

	var b strings.Builder
	b.WriteString(`---
title: "Algorithms"
weight: 1
description: "Every cryptographic algorithm the CBOM detector recognises, with its post-quantum posture."
---

`)
	b.WriteString("Each algorithm below maps to a CycloneDX `cryptographic-asset` component. Aliases are matched case/separator-insensitively and stored under the canonical SPDX name.\n\n")
	b.WriteString("> Generated from the catalog. To add or refine an algorithm, edit `internal/cbom/catalog/algorithms.json` and run `just gen-cbom`.\n\n")
	b.WriteString("| Algorithm | Primitive | PQC Status | Q-Level | Classical | OID |\n")
	b.WriteString("|-----------|-----------|------------|---------|-----------|-----|\n")
	for _, a := range algos {
		classical := "-"
		if a.ClassicalSecurityLevel > 0 {
			classical = strconv.Itoa(a.ClassicalSecurityLevel)
		}
		oid := "-"
		if a.OID != "" {
			oid = "`" + a.OID + "`"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %d | %s | %s |\n",
			a.Name, a.Primitive, a.PQCStatus, a.NISTQuantumLevel, classical, oid)
	}
	return b.String()
}

func standardsMD(cat *cbom.Catalog) string {
	// Collect the set of standards bodies across all algorithms.
	bodySet := map[string]bool{}
	for _, a := range cat.Algorithms {
		for body := range a.Standards {
			bodySet[body] = true
		}
	}
	bodies := make([]string, 0, len(bodySet))
	for b := range bodySet {
		bodies = append(bodies, b)
	}
	sort.Strings(bodies)

	algos := append([]cbom.AlgorithmDef(nil), cat.Algorithms...)
	sort.Slice(algos, func(i, j int) bool { return algos[i].Name < algos[j].Name })

	var b strings.Builder
	b.WriteString(`---
title: "Standards Matrix"
weight: 2
description: "Per-country/body approval status for each algorithm in the catalog."
---

`)
	b.WriteString("Approval status per standards body, drawn from published post-quantum guidance. An empty cell means the body has not specified a status for that algorithm in the catalog.\n\n")
	b.WriteString("> Generated from the catalog. Edit `internal/cbom/catalog/algorithms.json` and run `just gen-cbom`.\n\n")
	b.WriteString("| Algorithm |")
	for _, body := range bodies {
		fmt.Fprintf(&b, " %s |", body)
	}
	b.WriteString("\n|-----------|")
	for range bodies {
		b.WriteString("------|")
	}
	b.WriteByte('\n')
	for _, a := range algos {
		if len(a.Standards) == 0 {
			continue
		}
		fmt.Fprintf(&b, "| %s |", a.Name)
		for _, body := range bodies {
			fmt.Fprintf(&b, " %s |", emptyDash(a.Standards[body]))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatMD() string {
	return `---
title: "Catalog Format"
weight: 3
description: "The CBOM detection catalog schema, and how to extend or override it with --catalog."
---

All CBOM detection is driven by a declarative catalog so it can be maintained over time without code changes. The builtin catalog is embedded in the binary (` + "`internal/cbom/catalog/*.json`" + `). You can extend or replace it at runtime:

` + "```bash" + `
vulnetix cbom --catalog ./my-algos.json          # merge over the builtin (override by id)
vulnetix cbom --catalog ./only.json --no-builtin-catalog   # replace entirely
` + "```" + `

A catalog file is JSON with any of three top-level keys: ` + "`algorithms`, `libraries`, `call_extractors`" + `.

## Algorithm entry

` + "```jsonc" + `
{
  "id": "sha-256",                       // canonical SPDX id (override key)
  "name": "SHA-256",                     // canonical stored name
  "spdx_class": "Cryptographic-Hash-Function/Hash-Function",
  "oid": "2.16.840.1.101.3.4.2.1",
  "aliases": ["sha256", "sha_256", "sha2-256"],   // matched case/separator-insensitively
  "primitive": "hash",                   // CycloneDX algorithmProperties.primitive enum
  "crypto_functions": ["digest"],        // CycloneDX cryptoFunctions enum
  "classical_security_level": 128,
  "nist_quantum_security_level": 2,      // 0..6 (0 = not quantum-safe)
  "pqc_status": "quantum-safe",          // quantum-safe | quantum-vulnerable | deprecated | hybrid
  "standards": {"NIST": "approved", "BSI": "approved"},   // per-country matrix
  "source_patterns": {                   // language -> Go RE2 patterns (attribute this algorithm)
    "go": ["crypto/sha256"],
    "python": ["(?i)hashlib\\.sha256"]
  },
  "config_patterns": ["(?i)\\bSHA[_-]?256\\b"]   // matched in TLS/SSH/JWT/OpenSSL config
}
` + "```" + `

The ` + "`primitive`, `crypto_functions`, `mode`, `padding` and `pqc_status`" + ` values are validated against the CycloneDX enums at load time and by ` + "`just gen-cbom`" + `.

## Library entry

` + "```jsonc" + `
{
  "id": "liboqs",
  "name": "liboqs",
  "provider": "Open Quantum Safe",
  "languages": ["c", "cpp", "python", "go", "rust"],
  "purl_names": {"generic": "liboqs"},
  "import_patterns": ["#include\\s*<oqs/", "(?i)\\bOQS_(?:KEM|SIG)_"]
}
` + "```" + `

## Call extractor

A call extractor captures an algorithm token from a generic crypto API; the token is normalized and resolved through the alias index, so arbitrary spellings map to one algorithm.

` + "```jsonc" + `
{"languages": ["javascript"], "pattern": "(?i)createHash\\(\\s*['\"]([\\w./-]+)['\"]", "role": "algorithm"}
// role: "algorithm" | "transform" (Java AES/CBC/PKCS5Padding) | "jwt" ("alg":"…")
` + "```" + `

Each extractor pattern must have **exactly one capture group**. All patterns are Go RE2 (no backreferences/lookaround).
`
}
