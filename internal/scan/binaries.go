package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Package-manager binary resolution.
//
// A detected manifest implies a set of binaries that could resolve it (e.g.
// pyproject.toml → pip/uv/poetry/pdm/hatch/pipenv). A lockfile narrows that set
// to the single authoritative resolver (uv.lock → uv). This file maps detected
// files to candidate binaries, detects which are installed, and captures each
// binary's path + version using a per-binary version-command spec.

// manifestBinaries maps a manifest basename to the binaries that can resolve it.
var manifestBinaries = map[string][]string{
	"package.json":     {"npm", "yarn", "pnpm", "bun"},
	"pyproject.toml":   {"pip", "uv", "poetry", "pdm", "hatch", "pipenv"},
	"requirements.txt": {"pip", "uv"},
	"Pipfile":          {"pipenv", "pip"},
	"Gemfile":          {"bundle", "gem"},
	"pom.xml":          {"mvn"},
	"build.gradle":     {"gradle"},
	"build.gradle.kts": {"gradle"},
	"go.mod":           {"go"},
	"Cargo.toml":       {"cargo"},
	"composer.json":    {"composer"},
	"setup.py":         {"pip"},
	"environment.yml":  {"conda", "mamba"},
	"environment.yaml": {"conda", "mamba"},
	"project.clj":      {"lein"},
	"deps.edn":         {"clojure", "clj"},
	"bb.edn":           {"bb"},
	"packages.config":  {"nuget", "dotnet"},
}

// lockfileBinary maps a lockfile basename to the single binary it pins.
var lockfileBinary = map[string]string{
	"uv.lock":           "uv",
	"poetry.lock":       "poetry",
	"pdm.lock":          "pdm",
	"Pipfile.lock":      "pipenv",
	"package-lock.json": "npm",
	"yarn.lock":         "yarn",
	"pnpm-lock.yaml":    "pnpm",
	"bun.lock":          "bun",
	"bun.lockb":         "bun",
	"Gemfile.lock":      "bundle",
	"Cargo.lock":        "cargo",
	"composer.lock":     "composer",
	"go.sum":            "go",
	"gradle.lockfile":   "gradle",
}

// binaryEcosystem maps a binary to its ecosystem for the capability row.
var binaryEcosystem = map[string]string{
	"npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
	"pip": "pypi", "uv": "pypi", "poetry": "pypi", "pdm": "pypi", "hatch": "pypi", "pipenv": "pypi",
	"bundle": "rubygems", "gem": "rubygems",
	"mvn": "maven", "gradle": "maven",
	"go":       "golang",
	"cargo":    "cargo",
	"composer": "composer",
	"conda":    "conda", "mamba": "conda",
	"lein": "clojars", "clojure": "clojars", "clj": "clojars", "bb": "clojars",
	"nuget": "nuget", "dotnet": "nuget",
}

// binaryVersionArgs maps a binary to the argv used to print its version. Most
// accept "--version"; the exceptions (go, mvn) use their own subcommand/flag.
var binaryVersionArgs = map[string][]string{
	"npm": {"--version"}, "yarn": {"--version"}, "pnpm": {"--version"}, "bun": {"--version"},
	"pip": {"--version"}, "uv": {"--version"}, "poetry": {"--version"}, "pdm": {"--version"},
	"hatch": {"--version"}, "pipenv": {"--version"},
	"bundle": {"--version"}, "gem": {"--version"},
	"mvn": {"-v"}, "gradle": {"--version"},
	"go":       {"version"},
	"cargo":    {"--version"},
	"composer": {"--version"},
	"conda":    {"--version"}, "mamba": {"--version"},
	"lein": {"--version"}, "clojure": {"--version"}, "clj": {"--version"}, "bb": {"--version"},
	"nuget": {"help"}, "dotnet": {"--version"},
}

// semverRe extracts the first version-looking token from a binary's output.
var semverRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:[.\-+][0-9A-Za-z.\-]+)?`)

// ResolvedBinary describes one package-manager binary candidate on the host.
type ResolvedBinary struct {
	Ecosystem      string
	Binary         string
	BinaryPath     string
	Version        string
	VersionCommand string
	Detected       bool
	Authoritative  bool
}

// ResolvePackageManagerBinaries takes the set of manifest/lockfile basenames
// detected in the repo and returns one ResolvedBinary per candidate binary:
// whether it is installed (PATH), its resolved path + version, and whether a
// lockfile narrowed the manifest to this specific binary (Authoritative).
func ResolvePackageManagerBinaries(presentFiles []string) []ResolvedBinary {
	present := make(map[string]bool, len(presentFiles))
	for _, f := range presentFiles {
		present[f] = true
	}

	// Union candidate binaries across present manifests.
	candidates := map[string]bool{}
	for base := range present {
		for _, bin := range manifestBinaries[base] {
			candidates[bin] = true
		}
	}
	// Authoritative binaries from present lockfiles. These are always candidates.
	authoritative := map[string]bool{}
	for base := range present {
		if bin, ok := lockfileBinary[base]; ok {
			authoritative[bin] = true
			candidates[bin] = true
		}
	}

	// Version commands run concurrently: each is a process start, and some (gradle
	// starts a JVM) take over a second, so a manifest with six candidates waited on
	// six in a row.
	out := make([]ResolvedBinary, 0, len(candidates))
	for bin := range candidates {
		out = append(out, ResolvedBinary{
			Ecosystem:     binaryEcosystem[bin],
			Binary:        bin,
			Authoritative: authoritative[bin],
		})
	}
	var wg sync.WaitGroup
	for i := range out {
		rb := &out[i]
		path, err := exec.LookPath(rb.Binary)
		if err != nil {
			continue
		}
		rb.Detected = true
		rb.BinaryPath = path
		args := binaryVersionArgs[rb.Binary]
		if len(args) == 0 {
			args = []string{"--version"}
		}
		rb.VersionCommand = rb.Binary + " " + strings.Join(args, " ")
		wg.Add(1)
		go func() {
			defer wg.Done()
			rb.Version = binaryVersion(rb.Binary, path, args)
		}()
	}
	wg.Wait()
	return out
}

// runBinaryVersion executes `<bin> <args...>` with a short timeout and extracts
// the first semver-looking token from stdout/stderr. Returns "" on any failure.
func runBinaryVersion(bin string, args []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return semverRe.FindString(string(out))
}

// binaryVersion is runBinaryVersion with the answer remembered on disk. The key
// is the resolved executable's path, size and modification time plus the
// arguments, so the same file always reports the version it reported before,
// and an upgrade (a new file, or a new Cellar path) is asked again. Only a
// version found is stored. VULNETIX_NO_BINARY_CACHE disables the store.
func binaryVersion(bin, path string, args []string) string {
	key := binaryVersionKey(path, args)
	if key != "" {
		if raw, err := os.ReadFile(filepath.Join(binaryVersionDir, key)); err == nil && len(raw) > 0 {
			return string(raw)
		}
	}
	v := runBinaryVersion(bin, args)
	if v != "" && key != "" && os.MkdirAll(binaryVersionDir, 0o700) == nil {
		tmp, err := os.CreateTemp(binaryVersionDir, ".tmp-*")
		if err == nil {
			_, werr := tmp.WriteString(v)
			cerr := tmp.Close()
			if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(binaryVersionDir, key)) != nil {
				_ = os.Remove(tmp.Name())
			}
		}
	}
	return v
}

// binaryVersionDir is where versions persist; empty disables the store.
var binaryVersionDir = defaultBinaryVersionDir()

func defaultBinaryVersionDir() string {
	if os.Getenv("VULNETIX_NO_BINARY_CACHE") != "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulnetix", "cache", "binaries")
}

func binaryVersionKey(path string, args []string) string {
	if binaryVersionDir == "" {
		return ""
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	info, err := os.Stat(real)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s", real, info.Size(), info.ModTime().UnixNano(), strings.Join(args, "\x00"))))
	return hex.EncodeToString(sum[:16])
}
