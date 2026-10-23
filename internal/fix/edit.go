package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	manifest "github.com/Vulnetix/vdb-manifest"
)

func Apply(root string, plans []FixCandidate) error {
	for _, p := range plans {
		if p.Skipped || p.TargetVer == "" {
			continue
		}
		switch p.Method {
		case MethodParentUpdate:
			// No manifest edit: a Safe-Harbour child already satisfies the
			// parent's declared range, so the install command re-resolves it.
			continue
		case MethodParentUpgrade:
			// Bump the direct parent's declared range so the lockfile re-resolves
			// the vulnerable child to a safe version.
			if err := applyParentUpgrade(root, p); err != nil {
				return err
			}
			continue
		case MethodOverride:
			// Deterministically pin the vulnerable child via the ecosystem's
			// override / pin mechanism (cross-ecosystem).
			if err := applyOverride(root, p); err != nil {
				return err
			}
			continue
		}
		if err := applyOne(root, p); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(root string, p FixCandidate) error {
	path := filepath.Join(root, p.SourceFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	original := string(data)
	next, changed := editManifest(original, p)
	if !changed {
		return fmt.Errorf("could not locate %s in %s for autofix edit", p.PackageName, p.SourceFile)
	}
	return os.WriteFile(path, []byte(next), 0o644)
}

// applyParentUpgrade rewrites a direct parent dependency's declared range to the
// resolved parent target so the lockfile re-resolves the vulnerable child. If the
// parent cannot be located in the manifest, the install command remains the
// fallback (no error — the report still records the recommendation).
func applyParentUpgrade(root string, p FixCandidate) error {
	if p.ParentName == "" || p.ParentTarget == "" {
		return nil
	}
	path := filepath.Join(root, p.SourceFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Edit the PARENT dependency's declared version using the same per-manifest
	// logic as a direct bump, so parent-upgrade works across ecosystems
	// (package.json, go.mod, Cargo.toml, …) — not just npm.
	next, changed := editManifest(string(data), FixCandidate{
		PackageName: p.ParentName,
		Ecosystem:   p.Ecosystem,
		SourceFile:  p.SourceFile,
		TargetVer:   p.ParentTarget,
	})
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(next), 0o644)
}

// editManifest applies a direct version bump to one manifest's text. The
// writers live in github.com/Vulnetix/vdb-manifest.
func editManifest(content string, p FixCandidate) (string, bool) {
	return manifest.EditManifestText(p.SourceFile, content, p.PackageName, p.TargetVer)
}

// ApplyOverride pins the (transitive) package to its safe version via the
// package manager's override mechanism in the nearest package.json:
//
//	npm / bun → "overrides"
//	pnpm      → "pnpm": { "overrides" }
//	yarn      → "resolutions"
//
// No-op (nil) when no package.json is found in the manifest's directory.
func ApplyOverride(root string, p FixCandidate) error {
	if p.PackageName == "" || p.TargetVer == "" {
		return nil
	}
	dir := filepath.Dir(filepath.Join(root, p.SourceFile))
	path := filepath.Join(dir, "package.json")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return applyPackageJSONOverrides(path, p.PackageManager, map[string]string{p.PackageName: p.TargetVer})
}

// applyOverride realises a transitive override/pin for the candidate's ecosystem:
//
//	npm family  → package.json overrides/resolutions (ApplyOverride)
//	go, cargo   → no manifest edit; the install command (`go get …@safe && go mod
//	              tidy`, `cargo update -p … --precise safe`) performs the pin
//	pypi        → pin/append the child in requirements.txt (or pyproject)
//	maven       → add a <dependencyManagement> pin in pom.xml
//	composer    → add the child to "require" in composer.json
//	rubygems    → pin/append a gem entry in the Gemfile
//
// All edits are best-effort: when the manifest cannot be located or edited the
// install command still runs and the proof-of-work report records the pin.
func applyOverride(root string, p FixCandidate) error {
	switch strings.ToLower(p.Ecosystem) {
	case "npm":
		return ApplyOverride(root, p)
	case "golang", "cargo":
		return nil
	default:
		return applyTransitivePin(root, p)
	}
}

func applyTransitivePin(root string, p FixCandidate) error {
	if p.PackageName == "" || p.TargetVer == "" {
		return nil
	}
	path := filepath.Join(root, p.SourceFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	next, changed := pinTransitive(string(data), p)
	if !changed {
		return nil
	}
	return os.WriteFile(path, []byte(next), 0o644)
}

// pinTransitive forces the resolver to select the safe child version by editing
// the manifest with the ecosystem's pin mechanism, through the shared writers in
// github.com/Vulnetix/vdb-manifest. Returns (content, false) when no edit
// applies (the install command remains the fallback).
func pinTransitive(content string, p FixCandidate) (string, bool) {
	file := p.SourceFile
	if file == "" {
		return content, false
	}
	out, skipped, err := manifest.Apply(map[string]string{file: content}, []manifest.Change{{
		Name:           p.PackageName,
		Ecosystem:      p.Ecosystem,
		From:           p.CurrentVer,
		To:             p.TargetVer,
		Method:         manifest.MethodOverride,
		File:           file,
		PackageManager: p.PackageManager,
	}})
	if err != nil || len(skipped) > 0 {
		return content, false
	}
	return out[file], true
}

// applyPackageJSONOverrides merges the given name→version pins into package.json
// using the override style for the package manager. Shared by the planned
// override path and the npm peer-conflict install retry. The edit is made on the
// text, so the file's formatting is kept.
func applyPackageJSONOverrides(path, pm string, pins map[string]string) error {
	if len(pins) == 0 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	file := filepath.Base(path)
	names := make([]string, 0, len(pins))
	for name, ver := range pins {
		if name != "" && ver != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	changes := make([]manifest.Change, 0, len(names))
	for _, name := range names {
		changes = append(changes, manifest.Change{
			Name: name, Ecosystem: "npm", To: pins[name],
			Method: manifest.MethodOverride, File: file, PackageManager: pm,
		})
	}
	out, skipped, err := manifest.Apply(map[string]string{file: string(data)}, changes)
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		return fmt.Errorf("could not write override for %s in %s: %s", skipped[0].Change.Name, path, skipped[0].Reason)
	}
	if out[file] == string(data) {
		return nil
	}
	return os.WriteFile(path, []byte(out[file]), 0o644)
}

// EditManifestText applies a version bump to manifest content and returns the
// rewritten text, reporting whether anything changed.
//
// The file-based Apply path exists for the CLI, which owns the working tree.
// The language server does not: it holds the editor's unsaved buffer and must
// hand back a text edit for the editor to apply, so that the change lands in
// the user's undo history and cannot race a concurrent edit. Both go through
// the same per-ecosystem rewriters, so a fix suggested in the editor is the one
// `vulnetix fix` would have written.
func EditManifestText(content string, p FixCandidate) (string, bool) {
	return editManifest(content, p)
}
