// Package binpkg discovers packages from compiled artefacts — the case where a
// dependency exists in a container image or release archive but no manifest,
// lockfile or package database mentions it.
//
// Three evidence sources are read, all offline and metadata-only:
//
//   - Go build info embedded by the toolchain (ELF, PE, Mach-O and XCOFF):
//     the main module, every dependency module with its go.sum H1 hash, and the
//     toolchain itself (reported as the `stdlib` package in the Go ecosystem,
//     which is how Go toolchain advisories are indexed).
//   - Rust `cargo auditable` data (the zlib-compressed JSON in the ELF
//     `.dep-v0` section), including its crate-level dependency edges.
//   - JVM archives: Maven coordinates from `META-INF/maven/**/pom.properties`,
//     `MANIFEST.MF` attributes, or the archive filename, including jars nested
//     one level deep inside a fat/Spring-Boot jar.
//
// Nothing here executes the artefact or reads a byte of its payload beyond the
// metadata sections named above.
package binpkg

import (
	"bytes"
	"compress/zlib"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Discovery methods, written verbatim into Package.Method and surfaced as
// CycloneDX evidence on the component.
const (
	MethodGoBuildInfo    = "go-buildinfo"
	MethodCargoAuditable = "cargo-auditable"
	MethodJVMArchive     = "jvm-archive"
	MethodOSFileOwner    = "os-file-owner"
)

// Scope values mirror internal/scan's scope vocabulary without importing it —
// binpkg is deliberately dependency-free so it can be reused by the analyze and
// container paths.
const (
	ScopeProduction  = "production"
	ScopeDevelopment = "development"
)

// Package is one dependency recovered from a compiled artefact.
type Package struct {
	Name      string
	Version   string
	Ecosystem string
	Scope     string
	IsDirect  bool
	Method    string
	Detail    string
	// Confidence is how strongly the evidence identifies the package: "high" for
	// what the build tool itself recorded, "medium" for archive metadata a human
	// can set freely, "low" for a name/version read off a filename.
	Confidence string
	Checksum   string // go.sum-style H1 hash when the source provides one
	BinaryPath string
}

// Edge is a dependency relation between two discovered packages, expressed with
// the same "name@version" keys the caller uses to build bom-refs.
type Edge struct {
	From      string
	DependsOn []string
}

// Result is everything one artefact yielded.
type Result struct {
	// Format identifies what was recognised: "go", "rust", "jvm" or "" when the
	// artefact carries no package metadata at all.
	Format   string
	Packages []Package
	Edges    []Edge
	// Attributes are extra facts about the artefact itself (VCS revision, build
	// settings, toolchain) that belong on the binary component, not on a package.
	Attributes map[string]string
	// Errors records metadata that was present but unreadable. A file with no
	// metadata at all is not an error.
	Errors []string
}

// Empty reports whether the artefact produced nothing worth recording.
func (r Result) Empty() bool { return len(r.Packages) == 0 && len(r.Attributes) == 0 }

// FromArtifact dispatches on file shape: JVM archives by extension, everything
// else through the compiled-binary readers. It never returns an error — an
// unreadable or uninteresting file yields an empty Result, because callers walk
// whole container filesystems where most files are neither.
func FromArtifact(path string) Result {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jar", ".war", ".ear", ".hpi", ".jpi":
		return FromJVMArchive(path)
	}
	return FromBinary(path)
}

// FromBinary reads package metadata embedded in a compiled binary.
func FromBinary(path string) Result {
	res := Result{Attributes: map[string]string{}}
	appendGoBuildInfo(path, &res)
	appendCargoAuditable(path, &res)
	if len(res.Attributes) == 0 {
		res.Attributes = nil
	}
	return res
}

// ── Go ──────────────────────────────────────────────────────────────────────

func appendGoBuildInfo(path string, res *Result) {
	info, err := buildinfo.ReadFile(path)
	if err != nil || info == nil {
		return
	}
	res.Format = "go"

	if v := goToolchainVersion(info.GoVersion); v != "" {
		// Go toolchain and standard-library advisories are published against the
		// package name "stdlib" in the Go ecosystem — emit that, not a synthetic
		// "go" package no advisory database would match.
		res.Packages = append(res.Packages, Package{
			Name: "stdlib", Version: v, Ecosystem: "golang", Scope: ScopeProduction,
			IsDirect: true, Method: MethodGoBuildInfo, Detail: "go toolchain " + info.GoVersion,
			Confidence: "high", BinaryPath: path,
		})
		res.Attributes["go-version"] = info.GoVersion
	}

	mainKey := ""
	if info.Main.Path != "" {
		res.Attributes["go-main-module"] = info.Main.Path
		if v := cleanModuleVersion(info.Main.Version); v != "" {
			mainKey = info.Main.Path + "@" + v
			res.Packages = append(res.Packages, Package{
				Name: info.Main.Path, Version: v, Ecosystem: "golang", Scope: ScopeProduction,
				IsDirect: true, Method: MethodGoBuildInfo, Detail: "main module",
				Confidence: "high", Checksum: info.Main.Sum, BinaryPath: path,
			})
		}
	}

	var deps []string
	for _, mod := range info.Deps {
		if mod == nil {
			continue
		}
		// A replaced module is what actually got linked; record the replacement
		// and note what it stood in for.
		detail := "linked module"
		effective := mod
		if mod.Replace != nil {
			effective = mod.Replace
			detail = "replaces " + mod.Path + "@" + mod.Version
		}
		version := cleanModuleVersion(effective.Version)
		if effective.Path == "" || version == "" {
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name: effective.Path, Version: version, Ecosystem: "golang", Scope: ScopeProduction,
			Method: MethodGoBuildInfo, Detail: detail, Confidence: "high",
			Checksum: effective.Sum, BinaryPath: path,
		})
		deps = append(deps, effective.Path+"@"+version)
	}
	if mainKey != "" && len(deps) > 0 {
		res.Edges = append(res.Edges, Edge{From: mainKey, DependsOn: deps})
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs", "vcs.revision", "vcs.time", "vcs.modified", "GOARCH", "GOOS", "GOAMD64", "CGO_ENABLED", "-ldflags", "-tags", "-trimpath", "-buildmode":
			if s.Value != "" {
				res.Attributes["go-build/"+strings.TrimPrefix(s.Key, "-")] = s.Value
			}
		}
	}
	if info.Path != "" {
		res.Attributes["go-main-package"] = info.Path
	}
}

// goVersionShape matches the release part of a toolchain version and nothing
// else, so experiment/GOEXPERIMENT suffixes ("go1.26.5-X:nodwarf5",
// "go1.24.2 X:nocoverageredesign") do not end up inside the version an advisory
// database is asked to match.
var goVersionShape = regexp.MustCompile(`^(\d+(?:\.\d+){0,2}(?:(?:rc|beta|alpha)\d+)?)`)

// goToolchainVersion turns a build-info Go version ("go1.24.2", "devel go1.25-…")
// into a bare release version. Development toolchains have no comparable version,
// so they are skipped rather than reported as a matchable release.
func goToolchainVersion(goVersion string) string {
	v := strings.TrimSpace(goVersion)
	if v == "" || strings.HasPrefix(v, "devel") {
		return ""
	}
	m := goVersionShape.FindStringSubmatch(strings.TrimPrefix(v, "go"))
	if m == nil {
		return ""
	}
	return m[1]
}

// cleanModuleVersion drops versions that identify no released artefact.
func cleanModuleVersion(v string) string {
	v = strings.TrimSpace(v)
	switch v {
	case "", "(devel)", "devel", "unknown":
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// ── Rust (cargo auditable) ──────────────────────────────────────────────────

// cargoAuditableSections are the section names `cargo auditable` has used for
// its dependency list; the current one is `.dep-v0`.
var cargoAuditableSections = []string{".dep-v0", "dep-v0"}

type cargoAuditableDoc struct {
	Packages []struct {
		Name         string `json:"name"`
		Version      string `json:"version"`
		Source       string `json:"source"`
		Kind         string `json:"kind"`
		Dependencies []int  `json:"dependencies"`
		Root         bool   `json:"root"`
	} `json:"packages"`
}

func appendCargoAuditable(path string, res *Result) {
	raw, err := readELFSection(path, cargoAuditableSections)
	if err != nil || len(raw) == 0 {
		return
	}
	decodeCargoAuditable(raw, path, res)
}

// decodeCargoAuditable inflates and decodes a `.dep-v0` payload. Split from the
// ELF read so the decode path is testable without synthesising an object file.
func decodeCargoAuditable(raw []byte, path string, res *Result) {
	data, err := inflate(raw)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("%s: cargo-auditable section is not zlib data: %v", path, err))
		return
	}
	var doc cargoAuditableDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("%s: cargo-auditable JSON: %v", path, err))
		return
	}
	if len(doc.Packages) == 0 {
		return
	}
	if res.Format == "" {
		res.Format = "rust"
	} else {
		res.Format += "+rust"
	}

	keys := make([]string, len(doc.Packages))
	for i, p := range doc.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		keys[i] = p.Name + "@" + p.Version
		scope := ScopeProduction
		if p.Kind == "build" || p.Kind == "dev" {
			scope = ScopeDevelopment
		}
		detail := "cargo auditable"
		if p.Source != "" {
			detail += " (" + p.Source + ")"
		}
		res.Packages = append(res.Packages, Package{
			Name: p.Name, Version: p.Version, Ecosystem: "cargo", Scope: scope,
			IsDirect: p.Root, Method: MethodCargoAuditable, Detail: detail,
			Confidence: "high", BinaryPath: path,
		})
	}
	for i, p := range doc.Packages {
		if keys[i] == "" || len(p.Dependencies) == 0 {
			continue
		}
		var on []string
		for _, idx := range p.Dependencies {
			if idx >= 0 && idx < len(keys) && keys[idx] != "" {
				on = append(on, keys[idx])
			}
		}
		if len(on) > 0 {
			res.Edges = append(res.Edges, Edge{From: keys[i], DependsOn: on})
		}
	}
	if res.Attributes == nil {
		res.Attributes = map[string]string{}
	}
	res.Attributes["cargo-auditable"] = "true"
}

func readELFSection(path string, names []string) ([]byte, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	for _, name := range names {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		// Data() applies the section's own decompression when SHF_COMPRESSED is set.
		data, err := sec.Data()
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			return data, nil
		}
	}
	return nil, nil
}

// maxInflated bounds decompression of embedded metadata so a crafted artefact
// cannot turn an SBOM run into a memory exhaustion.
const maxInflated = 32 << 20

func inflate(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxInflated))
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ── Sorting helper ──────────────────────────────────────────────────────────

// Dedupe collapses packages that were discovered more than once (the same module
// linked into several binaries), keeping the first occurrence's provenance and
// merging nothing but direct-ness, and returns them in a stable order.
func Dedupe(pkgs []Package) []Package {
	index := map[string]int{}
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		key := strings.ToLower(p.Ecosystem + ":" + p.Name + "@" + p.Version + ":" + p.BinaryPath)
		if idx, ok := index[key]; ok {
			if p.IsDirect {
				out[idx].IsDirect = true
			}
			continue
		}
		index[key] = len(out)
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// LooksExecutable reports whether a file is worth handing to FromBinary: an ELF,
// PE, Mach-O or XCOFF magic number, or a JVM archive extension. Callers use it to
// avoid reading every file in a container filesystem twice.
func LooksExecutable(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jar", ".war", ".ear", ".hpi", ".jpi":
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	switch {
	case bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}): // ELF
		return true
	case magic[0] == 'M' && magic[1] == 'Z': // PE / DOS stub
		return true
	case bytes.Equal(magic[:], []byte{0xfe, 0xed, 0xfa, 0xce}), // Mach-O 32 BE
		bytes.Equal(magic[:], []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.Equal(magic[:], []byte{0xfe, 0xed, 0xfa, 0xcf}), // Mach-O 64
		bytes.Equal(magic[:], []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.Equal(magic[:], []byte{0xca, 0xfe, 0xba, 0xbe}): // universal / fat
		return true
	case magic[0] == 0x01 && (magic[1] == 0xdf || magic[1] == 0xf7): // XCOFF
		return true
	}
	return false
}
