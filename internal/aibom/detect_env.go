package aibom

import (
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"
)

// detectEnv records which catalog env-var names are present in the environment.
// Only the variable NAME and its presence are ever recorded — the value is never
// read, copied, or emitted, so secrets never leak into the AIBOM.
func (c *collector) detectEnv(environ []string) {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == "" {
			continue
		}
		for i := range c.cat.Tools {
			t := &c.cat.Tools[i]
			if envMatches(t, name) {
				h := c.tool(t.Def)
				h.methods["env"] = true
				h.counts["env"]++
				if len(h.evidence) < maxEvidenceCollect {
					h.evidence = append(h.evidence, cdx.AIEvidence{
						Method: "env", Category: "env", Locator: name,
					})
				}
			}
		}
	}
}

func envMatches(t *CompiledTool, name string) bool {
	if t.EnvExact[name] {
		return true
	}
	for _, re := range t.EnvGlobs {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
