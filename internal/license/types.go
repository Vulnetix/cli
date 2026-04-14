package license

// Category classifies a license by its copyleft characteristics.
type Category string

const (
	CategoryPermissive     Category = "permissive"
	CategoryWeakCopyleft   Category = "weak-copyleft"
	CategoryStrongCopyleft Category = "strong-copyleft"
	CategoryProprietary    Category = "proprietary"
	CategoryPublicDomain   Category = "public-domain"
	CategoryUnknown        Category = "unknown"
)

// LicenseRecord describes a single SPDX license entry.
type LicenseRecord struct {
	SpdxID        string   `json:"spdxId" yaml:"spdx_id"`
	Name          string   `json:"name" yaml:"name"`
	Category      Category `json:"category" yaml:"category"`
	IsOsiApproved bool     `json:"isOsiApproved" yaml:"osi_approved"`
	IsFsfLibre    bool     `json:"isFsfLibre" yaml:"fsf_libre"`
	IsDeprecated  bool     `json:"isDeprecated" yaml:"deprecated"`
}

// PackageLicense ties a detected package to its resolved license.
type PackageLicense struct {
	PackageName    string         `json:"packageName"`
	PackageVersion string         `json:"packageVersion"`
	Ecosystem      string         `json:"ecosystem"`
	Scope          string         `json:"scope"`
	LicenseSpdxID  string         `json:"licenseSpdxId"`
	LicenseSource  string         `json:"licenseSource"` // "manifest", "lockfile", "embedded-db"
	SourceFile      string         `json:"sourceFile"`
	IsDirect        bool           `json:"isDirect"`
	GitHubURL       string         `json:"-"` // optional: "owner/repo" from manifest, used for license resolution
	Record          *LicenseRecord `json:"record,omitempty"`
	IntroducedPaths [][]string     `json:"introducedPaths,omitempty"`
	PathCount       int            `json:"pathCount,omitempty"`
}

// LicenseConflict describes an incompatibility between two licenses.
type LicenseConflict struct {
	Type           string `json:"type"`     // "incompatible", "copyleft-mixing", "deprecated", "version-incompatible"
	Severity       string `json:"severity"` // critical, high, medium, low
	License1       string `json:"license1"`
	License2       string `json:"license2"`
	Package1       string `json:"package1"`
	Package2       string `json:"package2"`
	Description    string     `json:"description"`
	Recommendation string     `json:"recommendation"`
	Package1Paths  [][]string `json:"package1Paths,omitempty"`
	Package2Paths  [][]string `json:"package2Paths,omitempty"`
}

// EvidenceStep is one step in a rule evaluation trace.
type EvidenceStep struct {
	Rule     string `json:"rule"`
	Input    string `json:"input"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Result   string `json:"result"` // "PASS" or "FAIL"
}

// Finding is a single license issue produced by evaluation.
type Finding struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Confidence  float64        `json:"confidence"`
	Package         PackageLicense `json:"package"`
	Category        string         `json:"category"` // rule category
	Evidence        []EvidenceStep `json:"evidence"`
	IntroducedPaths [][]string     `json:"introducedPaths,omitempty"`
	PathCount       int            `json:"pathCount,omitempty"`
}

// AnalysisSummary provides aggregate counts.
type AnalysisSummary struct {
	TotalPackages  int              `json:"totalPackages"`
	LicenseCounts  map[string]int   `json:"licenseCounts"`
	CategoryCounts map[Category]int `json:"categoryCounts"`
	ConflictCount  int              `json:"conflictCount"`
	FindingsBySev  map[string]int   `json:"findingsBySeverity"`
	OsiApproved    int              `json:"osiApproved"`
	FsfLibre       int              `json:"fsfLibre"`
	Deprecated     int              `json:"deprecated"`
	Unknown        int              `json:"unknown"`
}

// AnalysisResult is the complete output of a license analysis run.
type AnalysisResult struct {
	Mode      string            `json:"mode"`
	Packages  []PackageLicense  `json:"packages"`
	Conflicts []LicenseConflict `json:"conflicts"`
	Findings  []Finding         `json:"findings"`
	Summary   AnalysisSummary   `json:"summary"`
}

// EvalConfig controls evaluation behaviour.
type EvalConfig struct {
	Mode              string   // "inclusive" or "individual"
	AllowedLicenses   []string // SPDX IDs; empty = no allow list
	SeverityThreshold string   // "critical", "high", "medium", "low"
}
