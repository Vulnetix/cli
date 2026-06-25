package aibom

import (
	cdx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// detectSource scans file contents for AI-SDK usage and extracts the model-name
// literals bound to known SDK parameters. A library's extractors run only on
// files whose language matches the library and whose content matches one of the
// library's import patterns — so the same `model=` form is not mis-attributed
// across languages or to non-AI code.
func (c *collector) detectSource(input *sast.ScanInput) {
	if input == nil {
		return
	}
	if input.FileContents == nil {
		sast.LoadFileContents(input, maxSourceFileSize)
	}

	for path, content := range input.FileContents {
		langs := sast.LanguagesForPath(path)
		if len(langs) == 0 {
			continue
		}
		for i := range c.cat.Libraries {
			lib := &c.cat.Libraries[i]
			if !intersect(lib.Langs, langs) {
				continue
			}
			if !anyMatch(lib.Imports, content) {
				continue
			}
			c.libUsage(lib.Def, path)
			for _, me := range lib.Models {
				for _, ex := range findSubmatches(content, me.Re) {
					loc := path
					if ex.line > 0 {
						loc = path + ":" + itoa(ex.line)
					}
					snippet := ex.value
					if me.Param != "" {
						snippet = me.Param + "=" + ex.value
					}
					c.addModel(ex.value, lib.Def.Provider, lib.Def.ID, me.Task, cdx.AIEvidence{
						Method: "source", Category: "model", Locator: loc, Snippet: snippet,
					})
				}
			}
		}
	}
}

func (c *collector) libUsage(def LibraryDef, path string) {
	h := c.libs[def.ID]
	if h == nil {
		h = &libHit{def: def}
		c.libs[def.ID] = h
	}
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, cdx.AIEvidence{Method: "source", Category: "import", Locator: path})
	}
}
