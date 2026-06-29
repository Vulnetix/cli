# Add a Cryptography BOM (CBOM) subcommand

## Context

Post-quantum cryptography (PQC) adoption is now a mandate: NIST has standardized ML-KEM,
ML-DSA and SLH-DSA, governments worldwide (CNSA 2.0, BSI, ACSC, CCCS, NUKIB, AIVD, NCSC,
plus Korea's HAETAE/AIMer/SMAUG-T/NTRU+) have issued differing approval lists, and the
broad timeline is "PQC-capable by 2030, quantum-resistant by 2035". To act on this an
organization first needs to **know where it uses cryptography** and **which of those
algorithms are quantum-vulnerable**.

This adds a `vulnetix cbom` subcommand — a sibling to `vulnetix aibom` — that scans every
file in a project for cryptographic usage in **code and config**, plus certificates/keys on
disk and declared crypto libraries, and emits a CycloneDX **Cryptography Bill of Materials**
(CBOM, CycloneDX 1.6+ `cryptographic-asset` components). Each algorithm is classified for
quantum posture (quantum-safe / quantum-vulnerable / deprecated / hybrid) and annotated with
the per-country approval matrix, so the CBOM doubles as a PQC-readiness/compliance artifact.

The design mirrors AIBOM exactly: a maintainable embedded catalog drives all detection, the
builder/validation lives in the shared `vdb-cyclonedx` module, results are written to
`.vulnetix/` and best-effort uploaded when authenticated.

## Decisions captured from the user

- **All four passes**: source-code crypto APIs, config & protocol crypto, certificates/keys
  on disk, declared crypto libraries.
- **PQC as an explicit property** on every crypto component (not only the schema's
  `nistQuantumSecurityLevel`).
- **Case/separator-insensitive matching, canonical SPDX naming**: `SHA256`, `Sha256`,
  `sha256`, `SHA_256` all detect the same asset and are stored under one canonical
  SPDX-standard name.
- **Posture summary + opt-in gate** (`--fail-on`); default exit 0.
- **Builder in the shared `vdb-cyclonedx` module** (parity with `BuildAIBOM`) → cross-repo
  release.
- **Both** quantum classification **and** the full per-country approval matrix.

---

## Architecture (mirror of AIBOM)

| Concern | AIBOM (reuse as template) | New for CBOM |
|---|---|---|
| Command | `cmd/aibom.go` | `cmd/cbom.go` |
| Detection package | `internal/aibom/` | `internal/cbom/` |
| Catalog | `internal/aibom/catalog/*.json` | `internal/cbom/catalog/*.json` |
| Docs generator | `internal/aibom/aibomgen/`, `just gen-aibom` | `internal/cbom/cbomgen/`, `just gen-cbom` |
| File walking | `sast.BuildScanInputWithOptions` | reuse unchanged |
| Builder + validate | `cyclonedx.BuildAIBOM` (shared module) | `cyclonedx.BuildCBOM` (shared module) |
| Upload | `client.CliAIBOM` → `/v2/cli.ai-bom` | `client.CliCBOM` → `/v2/cli.cbom` |
| Output file | `.vulnetix/ai-bom.cdx.json` | `.vulnetix/cbom.cdx.json` |

---

## 1. Shared module: `../vdb-cyclonedx/cbom.go` (new) + release

Add a `cbom.go` parallel to `aibom.go`. The shared `bom-1.6/1.7` schemas already define
`cryptographic-asset` + `cryptoProperties`, and `ValidateCycloneDX()` already validates
them (confirmed) — no schema work needed.

**Producer contract types** (mirror `AIDetections`):

```go
type CryptoDetections struct {
    Assets         []CryptoAsset `json:"assets,omitempty"`
    Libraries      []CryptoLib   `json:"libraries,omitempty"`
    Certificates   []CryptoCert  `json:"certificates,omitempty"`
    CatalogVersion string        `json:"catalogVersion,omitempty"`
    // posture rollup (counts by pqcStatus) for the summary + gate
    Summary        CryptoSummary `json:"summary,omitempty"`
}

type CryptoAsset struct {
    SPDXID                   string            // canonical SPDX id, e.g. "aes", "ml-kem"
    Name                     string            // canonical SPDX name, e.g. "AES-256-GCM"
    OID                      string
    Primitive                string            // CDX enum: block-cipher|hash|kem|signature|kdf|mac|...
    ParameterSetIdentifier   string            // "256", "ML-KEM-768", ...
    Mode                     string            // CDX enum: gcm|cbc|... (when known)
    Padding                  string            // CDX enum: oaep|pkcs1v15|... (when known)
    CryptoFunctions          []string          // CDX enum: encrypt|decrypt|sign|verify|...
    ClassicalSecurityLevel   int
    NISTQuantumSecurityLevel int               // 0..6
    PQCStatus                string            // quantum-safe|quantum-vulnerable|deprecated|hybrid
    Standards                map[string]string // country/body -> approval status
    Confidence               string
    Evidence                 []CryptoEvidence  // file:line + snippet, like AIEvidence
}
// CryptoLib (declared crypto library → library component),
// CryptoCert (parsed cert → certificate + related-crypto-material assets).
```

**Builder** (mirror `BuildAIBOM`/`BuildAIBOMDocument`):

```go
func BuildCBOM(det CryptoDetections, opts CBOMOptions) ([]byte, error)
func BuildCBOMDocument(det CryptoDetections, opts CBOMOptions) any
func ParseCBOM(data []byte) (*CBOMInventory, error)   // for backend persistence parity
```

- Reuse `CBOMOptions`/`CBOMProject` exactly like `AIBOMOptions`/`AIBOMProject` (git+system
  metadata, `buildProjectComponent` → `metadata.component` + `vulnetix:git/*`,`vulnetix:env/*`).
- Define private doc/component structs (`cbomDoc`, `cbomComp`) like `aibomDoc`/`aibomComp`,
  but `cbomComp` adds `CryptoProperties *cdxCryptoProperties` and the component `Type` is
  `"cryptographic-asset"`. The `cryptoProperties` object carries `assetType`,
  `algorithmProperties` (primitive/parameterSetIdentifier/mode/padding/cryptoFunctions/
  classicalSecurityLevel/nistQuantumSecurityLevel), `oid`, and for certs the
  `certificateProperties`/`relatedCryptoMaterialProperties` groups.
- Add a `vulnetix:cbom/*` property namespace (new `Prop*` consts next to the `PropAI*`
  block): `vulnetix:cbom/profile`, `/generator`, `/catalog-version`, and per component
  `vulnetix:cbom/pqc-status`, `/spdx-id`, `/classical-security-level`,
  `/nist-quantum-security-level`, and `vulnetix:cbom/standards/<body>` for the country matrix.
  PQC status is therefore surfaced **both** as the schema field and an explicit property.
- Validation path identical to `BuildAIBOM` (marshal → `ValidateCycloneDX` → error on first
  violation).

**Release order** (no `replace` exists in CLI go.mod; CLI consumes from the registry):
1. Implement + unit-test `cbom.go` in `../vdb-cyclonedx` (temporarily add
   `replace github.com/Vulnetix/vdb-cyclonedx => ../vdb-cyclonedx` to the CLI `go.mod` for
   local dev only).
2. Tag the shared module a new minor (next after the `v0.2.0` the CLI currently pins).
3. Bump CLI `go.mod` `require` to the new tag, **remove the temp replace**, `go mod tidy`
   (per repo convention — otherwise the Release workflow fails on go.sum).

---

## 2. CLI detection package `internal/cbom/`

Mirror `internal/aibom/` file-for-file:

- **`catalog.go`** — `//go:embed catalog/*.json`, `Catalog`/`Compiled*` types, `LoadCatalog`,
  `Compile()` (single regex/alias validation gate). Same merge-by-id + `--catalog` override.
- **`detect.go`** — `Detect(Options)` orchestrator + `collector`; reuses
  `sast.BuildScanInputWithOptions(abs, {MaxDepth, IgnoreGlobs, IgnoreGit:true})`. Pass flags:
  `ScanSource`, `ScanConfig`, `ScanCerts`, `ScanDeps`. Returns
  `cdx.CryptoDetections` (shared type).
- **`normalize.go`** — the canonicalization required by the user:
  `canonical(token) = lowercase, strip [-_ .], collapse` then look up in an alias→SPDXID map
  built from the catalog. So `SHA256`/`Sha256`/`sha256`/`SHA_256` → SPDX id `sha-256` and
  the stored `Name` is the catalog's canonical SPDX name. All passes funnel raw matches
  through this before recording an asset, and the collector dedups by SPDX id (+ parameter
  set), so variants merge into one component with combined evidence.
- **`detect_source.go`** — per-language crypto API pass. Catalog `source_patterns` keyed by
  language; confirm the crypto library/import is present (like AIBOM's import gate), then
  match call-site regexes that capture the algorithm token (and mode/padding/keysize when in
  the same construct, e.g. Java `Cipher.getInstance("AES/GCM/NoPadding")`, Node
  `createCipheriv('aes-256-gcm')`, Go `crypto/aes`+`cipher.NewGCM`). Reuse
  `findSubmatches`/`anyMatch`. Records file:line + snippet evidence.
- **`detect_config.go`** — config & protocol pass. Catalog `config_patterns` for TLS cipher
  suites & versions (`ssl_ciphers`, `ssl_protocols`, HAProxy/Apache), SSH
  `Ciphers`/`KexAlgorithms`/`MACs`, JWT `"alg"`, OpenSSL/IPsec. Emits protocol + algorithm
  assets; cipher-suite strings (e.g. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
  `X25519MLKEM768`) decompose into their constituent algorithms via catalog aliases.
- **`detect_certs.go`** — certificate/key pass. For `*.pem,*.crt,*.cer,*.der,*.key,*.pub`
  use `encoding/pem` + `crypto/x509` (stdlib, already available) to extract signature
  algorithm, public-key type & size, validity window → `certificate` +
  `related-crypto-material` + the underlying `algorithm` assets. No private-key material is
  read beyond type/size metadata.
- **`detect_deps.go`** — declared crypto-library pass. Catalog `libraries` with
  `import_patterns` + `purl_names` (openssl, bouncycastle, libsodium, liboqs, ring, tink,
  pyca/cryptography, …) → `library` components, exactly like AIBOM libraries. `--include-home`
  extends to user caches the same way AIBOM does.
- **`detect_*_test.go`** + **`catalog_test.go`** — fixtures per pass; an explicit
  normalization-equivalence test (`SHA256`/`Sha256`/`sha256`/`SHA_256` collapse to one asset).

### Catalog schema — `internal/cbom/catalog/` (single source of truth)

Split like AIBOM: `algorithms.json`, `libraries.json`, `protocols.json`. Algorithm entry:

```jsonc
{
  "id": "sha-256",                       // canonical SPDX id (override key)
  "name": "SHA-256",                     // canonical stored name
  "spdx_class": "Cryptographic-Hash-Function/Hash-Function",
  "oid": "2.16.840.1.101.3.4.2.1",
  "aliases": ["sha256", "sha_256", "sha-2-256"],   // matched case/separator-insensitively
  "primitive": "hash",                   // CycloneDX algorithmProperties.primitive enum
  "crypto_functions": ["digest"],        // CycloneDX cryptoFunctions enum
  "classical_security_level": 128,
  "nist_quantum_security_level": 0,      // 0 = not quantum-safe / n/a
  "pqc_status": "quantum-vulnerable",    // quantum-safe|quantum-vulnerable|deprecated|hybrid
  "standards": { "NIST": "approved", "BSI": "approved" },   // per-country matrix
  "source_patterns": {
    "go":     ["crypto/sha256"],
    "python": ["hashlib\\.sha256", "SHA256"],
    "java":   ["MessageDigest\\.getInstance\\(\"SHA-?256\"\\)"],
    "javascript": ["createHash\\(['\"]sha256['\"]\\)"]
  },
  "config_patterns": ["\\bSHA256\\b"]
}
```

**Seeding the catalog (single source of truth, generator-validated):**
- **Classical algorithms** from the SPDX cryptographic-algorithm-list YAML
  (`id`, `oid`, `name`, `cryptoClass`, key sizes) — the list lacks the PQC standards.
- **PQC supplement** (NIST + regional): ML-KEM(-512/768/1024), ML-DSA(-44/65/87),
  SLH-DSA, FN-DSA (Falcon), HQC, FrodoKEM, Classic McEliece, LMS/HSS, XMSS/XMSSMT,
  and HAETAE / AIMer / SMAUG-T / NTRU+.
- **Hybrid KEMs**: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 → `pqc_status:
  "hybrid"`, decompose into constituents.
- **`standards`** populated from the requirements table (NIST, CNSA 2.0, ACSC, CCCS, NUKIB,
  BSI, AIVD, NCSC + Korea) so each PQC/quantum-vulnerable algorithm carries its approval
  status per body.

### Generator `internal/cbom/cbomgen/main.go` + `just gen-cbom`

Mirror `aibomgen`: load + compile catalog (fails build on bad regex/alias/duplicate id),
write docs to `website/content/docs/cbom/` (`_index.md`, `algorithms.md`, `pqc-status.md`,
`standards-matrix.md`, `catalog-format.md`) and `website/content/docs/cli-reference/cbom.md`.
Add to `justfile`:

```make
gen-cbom:
    go run ./internal/cbom/cbomgen
    just fmt
```

---

## 3. CLI command `cmd/cbom.go`

Copy `cmd/aibom.go` and adapt. Flags:

- positional `[path]` + `--path`, `--depth`, `--ignore`
- `-o/--output` (`pretty|json|cyclonedx-json`), `--output-file`
  (default `.vulnetix/cbom.cdx.json`), `--spec-version` (`1.6|1.7`, default `1.7`)
- `--catalog`, `--no-builtin-catalog`
- pass toggles: `--no-source`, `--no-config`, `--no-certs`, `--no-deps`, `--include-home`
- `--fail-on` (`none` default | `quantum-vulnerable` | `deprecated` | comma-list) — opt-in
  CI gate; non-zero exit when a matching asset is present
- `--no-upload`

`runCBOM`: `LoadCatalog → Compile → cbom.Detect → cyclonedx.BuildCBOM → uploadCBOM (best
effort) → writeCBOMFile → terminal render`. Reuse `writeAIBOMFile` pattern, `aibomProject`
helper (rename/share as `bomProject`), `display.Table` for the summary
(quantum-vulnerable / quantum-safe / deprecated / hybrid counts) + asset/cert/library
tables. Evaluate `--fail-on` against `det.Summary` after writing the file and return a
non-zero error when breached.

**Optional `scan` hook** (defer unless requested): a best-effort `detectAndUploadCBOM`
mirroring `detectAndUploadAIBOM`, gated behind a `--no-cbom` flag, only uploading when assets
are found. Plan keeps this out of v1 scope; note as follow-up.

---

## 4. Upload `pkg/vdb/api_cli.go`

Add next to `CliAIBOM` (best-effort, community/unauth skipped, 180s timeout):

```go
type CliCBOMRequest struct {
    SpecVersion    string          `json:"specVersion"`
    CatalogVersion string          `json:"catalogVersion"`
    BomJSON        string          `json:"bomJson"`
    Detections     json.RawMessage `json:"detections"`
}
type CliCBOMResponse struct { Cbom *struct{ URL string `json:"url"` } `json:"cbom"` }
func (c *Client) CliCBOM(env CliEnv, req CliCBOMRequest) (*CliResponse[CliCBOMResponse], error) {
    return cliPostWithEnv[CliCBOMResponse](c, "cli.cbom", env, req)
}
```

`/v2/cli.cbom` does not exist in the backend yet; because upload is best-effort it degrades
to a logged-and-ignored 404 until the backend (vdb-api/saas, out of this repo's scope) adds
the endpoint and `ParseCBOM` persistence. Flag as a backend follow-up.

---

## Files to create / modify

**Create**
- `../vdb-cyclonedx/cbom.go`, `../vdb-cyclonedx/cbom_test.go`
- `cmd/cbom.go`
- `internal/cbom/{catalog.go,detect.go,normalize.go,detect_source.go,detect_config.go,detect_certs.go,detect_deps.go}` + `_test.go`
- `internal/cbom/catalog/{algorithms.json,libraries.json,protocols.json}`
- `internal/cbom/cbomgen/main.go`
- `website/content/docs/cbom/*` + `website/content/docs/cli-reference/cbom.md` (generated)

**Modify**
- CLI `go.mod`/`go.sum` (bump `vdb-cyclonedx` to the new release; `go mod tidy`)
- `pkg/vdb/api_cli.go` (`CliCBOM*`)
- `justfile` (`gen-cbom`)
- `AGENTS.md` (new "### CBOM Subcommand" section, mirroring AIBOM/Malscan)

---

## Verification

1. **Shared module**: `cd ../vdb-cyclonedx && go test ./...` — `BuildCBOM` output validates
   against `bom-1.6`/`bom-1.7` schemas (crypto-asset components, cryptoProperties enums).
2. **Normalization**: unit test asserting `SHA256`/`Sha256`/`sha256`/`SHA_256` produce one
   asset with canonical name `SHA-256` and merged evidence.
3. **Per-pass fixtures**: small fixtures under `internal/cbom/testdata/` (a Go file using
   `crypto/aes`+GCM and `crypto/md5`; an nginx conf with `ssl_ciphers`; a self-signed
   `cert.pem`; a `package.json` declaring a crypto lib) — assert expected primitives,
   `pqc_status`, and `standards`.
4. **Catalog/docs**: `just gen-cbom` succeeds and is idempotent (no diff on re-run);
   `just test`, `just fmt`, `just lint`.
5. **End-to-end** (`just dev`):
   - `./build/vulnetix cbom .` on this repo (Go crypto usage) → pretty summary; inspect
     `.vulnetix/cbom.cdx.json`.
   - `./build/vulnetix cbom -o cyclonedx-json` → pipe to validate; confirm
     `cryptographic-asset` components + `cryptoProperties` + `vulnetix:cbom/pqc-status` and
     `vulnetix:cbom/standards/*` properties.
   - `./build/vulnetix cbom --fail-on quantum-vulnerable; echo $?` → non-zero when RSA/AES-CBC
     etc. present; `--fail-on none` → 0.
   - `--no-config --no-certs --no-deps` → source-only; each toggle independently verified.
6. **Release dance**: confirm CLI builds against the **tagged** module with the temp
   `replace` removed before merge.

## Out of scope (follow-ups)
- Backend `/v2/cli.cbom` endpoint + `ParseCBOM` persistence (vdb-api/saas).
- `scan`/`sca` integration hook (`--no-cbom`).
