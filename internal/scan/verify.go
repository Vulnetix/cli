package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/cli/v3/internal/memory"
)

// VerifyLocationGone returns true when the finding evidence at loc is no
// longer present on disk. "Gone" means: the file is missing, OR the original
// snippet is not found within a ±lineSlack window around loc.StartLine.
//
// rootPath is prepended when loc.File is relative. When loc.Snippet is empty
// (older records without snippet capture) the verifier returns gone=false so
// the caller leaves the record untouched — we never auto-resolve on a guess.
func VerifyLocationGone(rootPath string, loc memory.Location, lineSlack int) (bool, string) {
	if loc.File == "" {
		return false, "no location to verify"
	}

	path := loc.File
	if !filepath.IsAbs(path) {
		path = filepath.Join(rootPath, path)
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, "file deleted"
		}
		return false, "cannot read file: " + err.Error()
	}
	defer f.Close()

	if loc.Snippet == "" {
		// Conservative: without a snippet we cannot prove absence.
		return false, "no snippet recorded; cannot verify"
	}

	needle := strings.TrimSpace(loc.Snippet)
	if needle == "" {
		return false, "snippet is whitespace only"
	}

	lower := loc.StartLine - lineSlack
	if lower < 1 {
		lower = 1
	}
	upper := loc.StartLine + lineSlack
	if loc.EndLine > 0 && loc.EndLine+lineSlack > upper {
		upper = loc.EndLine + lineSlack
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo < lower {
			continue
		}
		if lineNo > upper {
			break
		}
		if strings.Contains(scanner.Text(), needle) {
			return false, "snippet still present"
		}
	}
	if err := scanner.Err(); err != nil {
		return false, "scan error: " + err.Error()
	}

	return true, "snippet absent at original location"
}
