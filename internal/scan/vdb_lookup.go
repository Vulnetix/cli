package scan

// VulnFinding represents a vulnerability found during a local scan. It is
// populated from the CycloneDX document returned by /v2/cli.sca (see
// SynthesiseFromCDX) and consumed throughout the scan/report pipeline.
type VulnFinding struct {
	CveID          string
	PackageName    string
	PackageVer     string
	Ecosystem      string
	Scope          string
	Severity       string
	Score          float64
	MetricType     string
	VectorString   string
	SourceFile     string
	Source         string // upstream vulnerability source name (empty = vulnetix)
	InCisaKev      bool
	InVulnCheckKev bool
	InEuKev        bool
	ExploitCount   int
}

// LookupStats summarises the outcome of a VDB lookup. /v2/cli.sca populates it
// via SynthesiseFromCDX so the report layer can show coverage counts.
type LookupStats struct {
	Total     int // unique packages queried (after dedup)
	Succeeded int // packages resolved successfully
	Failed    int // packages that errored
	Skipped   int // packages skipped (name too short)
	Cancelled int // packages not attempted
}
