package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/sast"
	"github.com/vulnetix/cli/v4/internal/scan"
)

// A scoped scan is one leg of a repository: `sast --language python` or
// `sca --package-manager npm`. What keeps a leg from damaging the others:
//
//   - It writes its own artifacts (sast.python.sarif, sbom.npm.cdx.json), so
//     parallel legs and the whole-repository SBOM never overwrite each other.
//   - It publishes to its own code scanning category, since an alert closes only
//     against a later upload in its category.
//   - It reports under its own tool name, so the server compares it only with
//     earlier runs of the same leg. A finding missing from a leg is compared
//     with what that leg scans, never with what another leg found.
//   - It skips absence-based SCA memory: the local memory holds every manager's
//     findings, and a leg cannot tell "fixed" from "not in my scope".

// scanScopeSlug is this process's leg; the submit paths read it because they
// sit below the options that carry it. Empty on a full scan.
var scanScopeSlug string

// addLanguageScopeFlags adds the flags of `sast`.
func addLanguageScopeFlags(cmd *cobra.Command) {
	names := strings.Join(sast.ScopeLanguages(), ", ")
	cmd.Flags().StringSlice("language", nil, "Scan only the files of these languages, comma-separated or repeated: "+names+". A file belongs to exactly one language; typescript is javascript")
	cmd.Flags().StringSlice("not-language", nil, "Scan everything except the files of these languages; the rest step beside --language jobs, so their union is the whole repository")
}

// addManagerScopeFlags adds the flags of `sca`.
func addManagerScopeFlags(cmd *cobra.Command) {
	names := strings.Join(scan.PackageManagers(), ", ")
	cmd.Flags().StringSlice("package-manager", nil, "Scan only the manifests of these package managers, comma-separated or repeated: "+names)
	cmd.Flags().StringSlice("not-package-manager", nil, "Scan everything except the manifests of these package managers, including committed SBOMs and packages named in CI pipelines and shell scripts")
}

// scopedArtifact names a leg's file under .vulnetix: sast.python.sarif.
func scopedArtifact(stem, slug, ext string) string {
	if slug == "" {
		return stem + "." + ext
	}
	return stem + "." + slug + "." + ext
}

// scopedToolName is the tool name a leg reports under. It keys the server's
// finding history, so it must stay stable for a leg.
func scopedToolName(name, slug string) string {
	if slug == "" {
		return name
	}
	return fmt.Sprintf("%s %s", name, slug)
}
