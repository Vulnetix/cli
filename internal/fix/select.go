package fix

import (
	"fmt"
	"path/filepath"
)

func SelectManifests(plans []FixCandidate, manifest string, yes bool) ([]FixCandidate, error) {
	if manifest == "" {
		return plans, nil
	}
	var out []FixCandidate
	for _, p := range plans {
		if filepath.Clean(p.SourceFile) == filepath.Clean(manifest) || filepath.Base(p.SourceFile) == filepath.Base(manifest) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--sca-autofix-manifest %q did not match any fixable finding", manifest)
	}
	return out, nil
}
