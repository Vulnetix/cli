package cbom

import (
	"path/filepath"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// maxDepsScanBytes caps the size of a file scanned for crypto-library imports.
// Manifests and source files are small; large files are data.
const maxDepsScanBytes = 512 * 1024

// manifestNames are dependency manifests/lockfiles that declare libraries but
// carry no programming-language signal, so they must be allow-listed explicitly.
var manifestNames = map[string]bool{
	"go.mod": true, "go.sum": true, "package.json": true, "requirements.txt": true,
	"pyproject.toml": true, "pipfile": true, "cargo.toml": true, "cargo.lock": true,
	"gemfile": true, "composer.json": true, "pom.xml": true,
	"build.gradle": true, "build.gradle.kts": true,
}

// detectDeps records declared cryptographic libraries. Only source files (with a
// recognized language) and known manifests are scanned — data files (no language,
// not a manifest) are skipped, mirroring the source pass. A library's import
// patterns are gated to its languages so a Python pattern doesn't fire on Go.
func (c *collector) detectDeps(input *sast.ScanInput) {
	if input == nil {
		return
	}
	for path, content := range input.FileContents {
		if len(content) > maxDepsScanBytes {
			continue
		}
		langs := sast.LanguagesForPath(path)
		if len(langs) == 0 && !manifestNames[strings.ToLower(filepath.Base(path))] {
			continue
		}
		for i := range c.cat.Libraries {
			l := &c.cat.Libraries[i]
			if len(langs) > 0 && len(l.Def.Languages) > 0 && !intersectLangSlice(l.Def.Languages, langs) {
				continue
			}
			for _, re := range l.Imports {
				if loc := re.FindStringIndex(content); loc != nil {
					line := 1 + strings.Count(content[:loc[0]], "\n")
					c.addLib(l.Def, cdx.CryptoEvidence{
						Method: "dependency", Category: "import",
						Locator: locOf(path, line), Snippet: trimSnippet(content[loc[0]:loc[1]]),
					})
					break
				}
			}
		}
	}
}
