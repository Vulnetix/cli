package scan

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/vulnetix/cli/internal/filetree"
	"github.com/vulnetix/cli/internal/gitctx"
)

// version is injected at build time via ldflags.
var version = "dev"

// ScanPayload is the JSON metadata sent alongside manifest files.
type ScanPayload struct {
	Version      string                   `json:"version"`
	CLI          CLIInfo                  `json:"cli"`
	Git          *gitctx.GitContext       `json:"git,omitempty"`
	FileTree     *filetree.FileTreeContext `json:"fileTree,omitempty"`
	ManifestType string                   `json:"manifestType"`
	Ecosystem    string                   `json:"ecosystem"`
	Timestamp    int64                    `json:"timestamp"`
}

// CLIInfo identifies the CLI version and platform.
type CLIInfo struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

// BuildPayload constructs a ScanPayload for a manifest file and marshals it to JSON.
// gitCtx may be nil (non-git directory). repoRoot may be empty.
func BuildPayload(file DetectedFile, gitCtx *gitctx.GitContext, repoRoot string) ([]byte, error) {
	ecosystem := ""
	manifestType := ""
	if file.ManifestInfo != nil {
		ecosystem = file.ManifestInfo.Ecosystem
		manifestType = file.ManifestInfo.Type
	}

	payload := ScanPayload{
		Version: "1",
		CLI: CLIInfo{
			Version:  version,
			Platform: runtime.GOOS + "/" + runtime.GOARCH,
		},
		Git:          gitCtx,
		FileTree:     filetree.Collect(file.Path, repoRoot, ecosystem),
		ManifestType: manifestType,
		Ecosystem:    ecosystem,
		Timestamp:    time.Now().UnixMilli(),
	}

	return json.Marshal(payload)
}
