package cmd

import (
	"testing"

	"github.com/vulnetix/cli/v4/internal/sast"
)

func TestScopedArtifactNames(t *testing.T) {
	if got := scopedArtifact("sast", "", "sarif"); got != "sast.sarif" {
		t.Errorf("a full scan keeps its file name, got %q", got)
	}
	if got := scopedArtifact("sbom", "npm", "cdx.json"); got != "sbom.npm.cdx.json" {
		t.Errorf("a leg writes its own SBOM, got %q", got)
	}
}

// The tool name keys the server's history: two legs must never share one, or
// the second would close the first's findings as disappeared.
func TestScopedToolNames(t *testing.T) {
	if got := scopedToolName("Vulnetix SAST", ""); got != "Vulnetix SAST" {
		t.Errorf("a full scan keeps its tool name, got %q", got)
	}
	py, js := scopedToolName("Vulnetix SAST", "python"), scopedToolName("Vulnetix SAST", "javascript")
	if py == js || py != "Vulnetix SAST python" {
		t.Errorf("legs must differ: %q, %q", py, js)
	}
}

// A clean leg still uploads, into its own category, which is what closes the
// alerts a fix resolved.
func TestCleanLegPublishesToItsCategory(t *testing.T) {
	byKind := codeScanningLogs(nil, []string{sast.ScopedKind("sast", "python")})
	l, ok := byKind["sast/python"]
	if !ok {
		t.Fatalf("no sast/python upload: %v", byKind)
	}
	if id := l.Runs[0].AutomationDetails.ID; id != "vulnetix/sast/python/" {
		t.Errorf("category = %q", id)
	}
}

func TestScanScopeFlagsLiveOnTheirCommand(t *testing.T) {
	if sastCmd.Flags().Lookup("language") == nil || sastCmd.Flags().Lookup("not-language") == nil {
		t.Error("sast must offer --language and --not-language")
	}
	if scaCmd.Flags().Lookup("package-manager") == nil || scaCmd.Flags().Lookup("not-package-manager") == nil {
		t.Error("sca must offer --package-manager and --not-package-manager")
	}
	if secretsCmd.Flags().Lookup("language") != nil {
		t.Error("secrets is not scoped by language")
	}
}
