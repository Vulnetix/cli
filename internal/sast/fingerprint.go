package sast

import (
	"crypto/sha256"
	"fmt"
)

// Fingerprint produces a stable hash identifying a finding by rule + location.
// Used as the dedup key in memory.yaml and the SARIF fingerprints map.
// Returns the first 16 hex characters of SHA-256("<RuleID>\x00<ArtifactURI>\x00<StartLine>").
func Fingerprint(ruleID, artifactURI string, startLine int) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d", ruleID, artifactURI, startLine))
	return fmt.Sprintf("%x", h[:8])
}
