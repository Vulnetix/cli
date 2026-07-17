package aibom

import (
	"regexp"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
)

// Terraform detection is regex-over-content, consistent with the rest of the
// CLI's IaC scanning (there is deliberately no HCL structural parser). Only
// the resource TYPE and, when the catalog demands it, an attribute pattern
// inside the block body are matched — resource names, variables and values
// are never interpreted.

var tfResourceHeader = regexp.MustCompile(`(?m)^\s*resource\s+"([\w-]+)"\s+"[^"]*"\s*\{`)

// maxTFBlockScan bounds how far into a resource block an attr_pattern is
// searched, so an unclosed brace in a malformed file cannot make this scan
// the rest of the file.
const maxTFBlockScan = 1 << 14 // 16 KiB

// evalTerraform matches catalog terraform_signals against a .tf/.tofu file.
func (c *collector) evalTerraform(p, content string) {
	if len(c.cat.Infra.Terraform) == 0 {
		return
	}
	for _, m := range tfResourceHeader.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 4 {
			continue
		}
		resourceType := content[m[2]:m[3]]
		line := 1 + strings.Count(content[:m[0]], "\n")
		var body string // extracted lazily, only when a signal needs it
		for i := range c.cat.Infra.Terraform {
			sig := &c.cat.Infra.Terraform[i]
			if !sig.ResourceRe.MatchString(resourceType) {
				continue
			}
			if sig.AttrRe != nil {
				if body == "" {
					body = tfBlockBody(content, m[1])
				}
				if !sig.AttrRe.MatchString(body) {
					continue
				}
			}
			h := c.infra(InfraRuntimeDef{
				ID:       sig.Def.ID,
				Name:     sig.Def.Name,
				Vendor:   sig.Def.Provider,
				Category: sig.Def.Category,
			})
			h.evidenceAdd(cdx.AIEvidence{
				Method: "iac", Category: "tf-resource",
				Locator: p + ":" + itoa(line), Snippet: resourceType,
			})
		}
	}
}

// tfBlockBody returns the body of a brace-delimited block starting just
// after the opening brace at offset. Brace counting is approximate (braces
// inside strings count too) but bounded and errs toward returning less.
func tfBlockBody(content string, offset int) string {
	end := offset + maxTFBlockScan
	if end > len(content) {
		end = len(content)
	}
	depth := 1
	for i := offset; i < end; i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return content[offset:i]
			}
		}
	}
	return content[offset:end]
}

// evalModelFiles reports model-weight artifacts present in the repository
// itself (.gguf, .safetensors, .onnx). The file exists, so there is no
// confidence gap — this is the strongest evidence the IaC pass produces.
func (c *collector) evalModelFiles(paths []string) {
	exts := c.cat.Infra.ModelFileExts
	if len(exts) == 0 {
		return
	}
	for _, p := range paths {
		idx := strings.LastIndexByte(p, '.')
		if idx < 0 || !exts[strings.ToLower(p[idx:])] {
			continue
		}
		c.addData(&dataHit{
			name:   p,
			kind:   "model-artifact",
			source: "file",
		}, cdx.AIEvidence{Method: "iac", Category: "model-file", Locator: p})
	}
}
