package vdb

// Wire types for POST /v2/cli.vex-ingest. Mirrors the vdb-api handler; the
// method itself is CliVexIngest in api_cli.go.

// Origins of a document sent to /v2/cli.vex-ingest.
const (
	VexOriginScanVexFile = "scan_vex_file"
	VexOriginBOMEnrich   = "bom_enrich"
	VexOriginUpload      = "upload"
	VexOriginBOMAnalysis = "bom_analysis"
	VexOriginTriage      = "triage"
	VexOriginReconcile   = "reconcile"
	VexOriginDefend      = "defend"
	VexOriginJail        = "jail"
)

// The server's limits: documents per request and bytes per document.
const (
	VexIngestMaxDocuments     = 10
	VexIngestMaxDocumentBytes = 8 << 20
)

// CliVexIngestRequest is the /v2/cli.vex-ingest payload.
type CliVexIngestRequest struct {
	Origin         string `json:"origin"`
	ScannerRunUuid string `json:"scannerRunUuid,omitempty"`
	// IngestionSnapshotUuid is the snapshot this run produced. /v2/cli.sca
	// answers with a snapshot uuid and no run uuid, so this is what lets the
	// server find the run when ScannerRunUuid is empty. Not in the shared
	// contract yet; a server that does not read it ignores it.
	IngestionSnapshotUuid string           `json:"ingestionSnapshotUuid,omitempty"`
	RepositoryFullName    string           `json:"repositoryFullName,omitempty"`
	GitCommit             string           `json:"gitCommit,omitempty"`
	Documents             []CliVexDocument `json:"documents"`
}

// CliVexDocument is one document, sent as base64 of its exact bytes.
type CliVexDocument struct {
	Path    string `json:"path"`
	Format  string `json:"format"` // openvex | cyclonedx | csaf
	Sha256  string `json:"sha256"`
	Content string `json:"content"`
}

// CliVexIngestResponse is the success body.
type CliVexIngestResponse struct {
	Documents []CliVexIngestResult `json:"documents"`
}

// CliVexIngestResult is what the server did with one document.
type CliVexIngestResult struct {
	Path         string   `json:"path"`
	OpenVexUuid  string   `json:"openVexUuid,omitempty"`
	ArtifactUuid string   `json:"artifactUuid,omitempty"`
	Format       string   `json:"format,omitempty"`
	Grounded     bool     `json:"grounded"`
	Statements   int      `json:"statements"`
	Created      []string `json:"created,omitempty"`
	Pending      []string `json:"pending,omitempty"`
	Linked       []string `json:"linked,omitempty"`
	Superseded   []string `json:"superseded,omitempty"`
	Triaged      int      `json:"triaged"`
	Applied      int      `json:"applied"`
	Error        string   `json:"error,omitempty"`
}
