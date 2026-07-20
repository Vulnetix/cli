package cmd

import (
	"encoding/json"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/malscan-engine/curation"
)

// fetchMalwareCuration pulls the global malware-curation consensus from the
// backend (best-effort; empty set when unauthenticated or offline) and builds
// the engine curation.Set so a local malscan honours community false-positive
// feedback before reporting.
func fetchMalwareCuration(git *gitctx.GitContext) *curation.Set {
	client := newCliClient()
	if client == nil {
		return curation.FromWire(curation.Wire{})
	}
	resp, err := client.CliMalwareCurationGet(envForCliWithGit(git))
	if err != nil || resp == nil {
		return curation.FromWire(curation.Wire{})
	}
	var w curation.Wire
	if raw, ok := resp.Data["curation"]; ok {
		if b, mErr := json.Marshal(raw); mErr == nil {
			_ = json.Unmarshal(b, &w)
		}
	}
	return curation.FromWire(w)
}

// filterMalscanByCuration drops IOCs and findings whose indicator a customer has
// marked false-positive. Returns the number dropped.
func filterMalscanByCuration(res *malscanResult, set *curation.Set) int {
	if set == nil || set.Empty() || res == nil {
		return 0
	}
	dropped := 0

	iocs := res.IOCs[:0]
	for _, i := range res.IOCs {
		if set.IOCFalsePositive(i.Type, i.Value) {
			dropped++
			continue
		}
		iocs = append(iocs, i)
	}
	res.IOCs = iocs

	finds := res.Findings[:0]
	for _, f := range res.Findings {
		if f.IOCType != "" && set.IOCFalsePositive(f.IOCType, f.IOCValue) {
			dropped++
			continue
		}
		finds = append(finds, f)
	}
	res.Findings = finds

	return dropped
}
