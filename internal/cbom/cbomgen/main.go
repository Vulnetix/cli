// Command cbomgen renders the CBOM detection documentation from the single
// source of truth: the embedded catalog (internal/cbom/catalog/*.json).
//
// It validates the catalog (every regex compiles, every CycloneDX enum value is
// in range) and then writes:
//   - website/content/docs/cbom/_index.md
//   - website/content/docs/cbom/algorithms.md
//   - website/content/docs/cbom/standards-matrix.md
//   - website/content/docs/cbom/catalog-format.md
//   - website/content/docs/cli-reference/cbom.md
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

	docs := filepath.Join(root, "website", "content", "docs")
	writes := map[string]string{
		filepath.Join(docs, "cbom", "_index.md"):           indexMD(cat),
		filepath.Join(docs, "cbom", "algorithms.md"):       algorithmsMD(cat),
		filepath.Join(docs, "cbom", "standards-matrix.md"): standardsMD(cat),
		filepath.Join(docs, "cbom", "catalog-format.md"):   formatMD(),
		filepath.Join(docs, "cli-reference", "cbom.md"):    commandMD(),
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

func indexMD(cat *cbom.Catalog) string {
	var b strings.Builder
	b.WriteString(`---
title: "CBOM"
weight: 8
description: "Discover cryptographic usage and emit a CycloneDX Cryptography Bill of Materials with post-quantum posture."
---

`)
	b.WriteString("The `vulnetix cbom` command discovers cryptographic algorithms, certificates and crypto libraries used in a project — in **source code and configuration** — and produces a **Cryptography Bill of Materials (CBOM)** in CycloneDX format, classifying each algorithm for **post-quantum** posture.\n\n")
	b.WriteString("> **This page is generated** from the detection catalog (`internal/cbom/catalog/*.json`). Run `just gen-cbom` after editing the catalog.\n\n")
	b.WriteString("## What it detects\n\n")
	b.WriteString("Four passes, all driven by a maintainable catalog:\n\n")
	b.WriteString("- **Source code** — per-language crypto API usage (Go `crypto/*`, Python `hashlib`/pyca, Java JCA, Node `crypto`, …) plus generic call extractors. Algorithm spellings are case/separator-insensitive: `SHA256`, `Sha256`, `sha256` and `SHA_256` all resolve to one canonical SPDX algorithm.\n")
	b.WriteString("- **Config** — TLS cipher suites & versions, SSH `Ciphers`/`KexAlgorithms`/`MACs`, JWT `alg`, OpenSSL/IPsec settings.\n")
	b.WriteString("- **Certificates** — X.509 certificates and keys on disk (signature algorithm, key type & size, validity). Only metadata is read — never key bytes.\n")
	b.WriteString("- **Dependencies** — declared crypto libraries (OpenSSL, Bouncy Castle, libsodium, liboqs, ring, Tink, pyca/cryptography, …).\n\n")
	b.WriteString("## Post-quantum posture\n\n")
	b.WriteString("Every algorithm is tagged `quantum-safe`, `quantum-vulnerable`, `deprecated` or `hybrid`, carries its CycloneDX `nistQuantumSecurityLevel` (0–6) and `classicalSecurityLevel`, and an annotated per-country approval matrix. Use `--fail-on quantum-vulnerable` (or `deprecated`) to gate CI.\n\n")
	fmt.Fprintf(&b, "The builtin catalog (version `%s`) covers **%d algorithms** and **%d crypto libraries**, including the NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA), FN-DSA, HQC, FrodoKEM, Classic McEliece, LMS/HSS, XMSS, the regional KpqC selections (HAETAE, AIMer, SMAUG-T, NTRU+) and the de-facto hybrid groups (X25519MLKEM768, …).\n\n",
		cat.Version, len(cat.Algorithms), len(cat.Libraries))
	b.WriteString("{{< cards >}}\n")
	b.WriteString("  {{< card link=\"algorithms\" title=\"Algorithms\" subtitle=\"Every algorithm the catalog detects and its PQC posture.\" icon=\"lock-closed\" >}}\n")
	b.WriteString("  {{< card link=\"standards-matrix\" title=\"Standards Matrix\" subtitle=\"Per-country approval status for PQC algorithms.\" icon=\"globe\" >}}\n")
	b.WriteString("  {{< card link=\"catalog-format\" title=\"Catalog Format\" subtitle=\"Extend or override detection with --catalog.\" icon=\"document-text\" >}}\n")
	b.WriteString("  {{< card link=\"../cli-reference/cbom\" title=\"Command Reference\" subtitle=\"vulnetix cbom flags and examples.\" icon=\"terminal\" >}}\n")
	b.WriteString("{{< /cards >}}\n")
	return b.String()
}

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

func commandMD() string {
	return `---
title: "CBOM Command Reference"
weight: 9
description: "Discover cryptographic usage and emit a CycloneDX Cryptography Bill of Materials with post-quantum posture."
---

The ` + "`cbom`" + ` command discovers cryptographic algorithms, certificates and crypto libraries in a project and produces a **Cryptography Bill of Materials (CBOM)** in CycloneDX format. See [CBOM](../cbom/) for what is detected and the catalog format.

## Usage

` + "```bash" + `
vulnetix cbom [path] [flags]
` + "```" + `

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| ` + "`--path`" + ` | string | ` + "`.`" + ` | Directory to scan (a positional ` + "`[path]`" + ` argument overrides this) |
| ` + "`--depth`" + ` | int | ` + "`25`" + ` | Maximum recursion depth for file discovery |
| ` + "`--ignore`" + ` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| ` + "`-o, --output`" + ` | string | ` + "`pretty`" + ` | Terminal output format: ` + "`pretty`, `json`, `cyclonedx-json`" + ` |
| ` + "`--output-file`" + ` | string | - | Path to write the CBOM (default: ` + "`<path>/.vulnetix/cbom.cdx.json`" + `) |
| ` + "`--spec-version`" + ` | string | ` + "`1.7`" + ` | CycloneDX spec version: ` + "`1.6`" + ` or ` + "`1.7`" + ` |
| ` + "`--catalog`" + ` | string | - | Catalog file to merge over (or replace) the builtin catalog |
| ` + "`--no-builtin-catalog`" + ` | bool | ` + "`false`" + ` | Do not load the embedded catalog (use only ` + "`--catalog`" + `) |
| ` + "`--no-source`" + ` | bool | ` + "`false`" + ` | Skip the source-code crypto API detection pass |
| ` + "`--no-config`" + ` | bool | ` + "`false`" + ` | Skip the config & protocol detection pass |
| ` + "`--no-certs`" + ` | bool | ` + "`false`" + ` | Skip the certificate / key detection pass |
| ` + "`--no-deps`" + ` | bool | ` + "`false`" + ` | Skip the crypto-library detection pass |
| ` + "`--fail-on`" + ` | string | ` + "`none`" + ` | Exit non-zero when crypto of these PQC statuses is found (e.g. ` + "`quantum-vulnerable`, `deprecated`" + `) |
| ` + "`--no-upload`" + ` | bool | ` + "`false`" + ` | Do not submit the CBOM to Vulnetix (submitted automatically when authenticated) |

## Output

- ` + "`pretty`" + ` (default) — a human-readable summary with the PQC posture rollup and per-algorithm tables.
- ` + "`cyclonedx-json`" + ` — the CycloneDX CBOM. Algorithms map to ` + "`cryptographic-asset`" + ` components (with ` + "`cryptoProperties`" + `), certificates to ` + "`cryptographic-asset`" + ` (` + "`assetType: certificate`" + `) plus a ` + "`related-crypto-material`" + ` key, and crypto libraries to ` + "`library`" + ` components. PQC posture and the standards matrix ride on ` + "`vulnetix:crypto/*`" + ` properties. The document is schema-validated before it is written.
- ` + "`json`" + ` — the raw detection result.

## Examples

` + "```bash" + `
vulnetix cbom                                   # pretty summary; writes .vulnetix/cbom.cdx.json
vulnetix cbom ./service -o cyclonedx-json        # print CycloneDX to stdout
vulnetix cbom --no-certs --no-deps              # source + config only
vulnetix cbom --fail-on quantum-vulnerable      # gate CI on quantum-vulnerable crypto
vulnetix cbom --catalog ./extra-algos.json      # extend the builtin catalog
` + "```" + `

## Privacy

The certificate pass reads only certificate/key **metadata** (algorithm, size, validity) — never key material. No source content is uploaded.
`
}
