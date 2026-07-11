package analyze

// The report model. Mirrors schemas/vulnetix-analyze-report.schema.json exactly — the
// schema is the contract and ValidateReport is run over the marshalled output before it is
// written or uploaded, so the two cannot drift without a test failing.
//
// The one thing worth reading carefully is Builder, below. Every reference tool surveyed
// (kospex, DevStats, github-metrics-aggregator, Measure, git-intelligence, …) emits metrics
// as bare numbers with no trail back to what produced them, and the discipline of keeping a
// number and its evidence in step is exactly the discipline that erodes first. So the
// builder does not let a collector emit a metric and its evidence separately: you hand it
// the evidence, and it derives the count. A collector cannot forget.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

type Report struct {
	SchemaVersion string       `json:"schemaVersion"`
	Tool          Tool         `json:"tool"`
	Target        Target       `json:"target"`
	Run           RunMeta      `json:"run"`
	Graph         *Graph       `json:"graph,omitempty"`
	Metrics       []Metric     `json:"metrics"`
	Evidence      *Evidence    `json:"evidence,omitempty"`
	Attachments   *Attachments `json:"attachments,omitempty"`
	Diagnostics   []Diagnostic `json:"diagnostics,omitempty"`
}

type Tool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Commit         string `json:"commit,omitempty"`
	CatalogVersion string `json:"catalogVersion,omitempty"`
}

type Target struct {
	RepoID          string `json:"repoId"`
	OrgKey          string `json:"orgKey,omitempty"`
	RemoteURL       string `json:"remoteUrl,omitempty"`
	DefaultBranch   string `json:"defaultBranch,omitempty"`
	HeadCommit      string `json:"headCommit,omitempty"`
	HeadCommittedAt string `json:"headCommittedAt,omitempty"`
	RootPath        string `json:"rootPath,omitempty"`
}

type RunMeta struct {
	StartedAt       string      `json:"startedAt"`
	CompletedAt     string      `json:"completedAt"`
	DurationSeconds float64     `json:"durationSeconds,omitempty"`
	HistoryWindow   *Window     `json:"historyWindow,omitempty"`
	Collectors      []Collector `json:"collectors,omitempty"`
}

type Window struct {
	Since         string `json:"since,omitempty"`
	Until         string `json:"until,omitempty"`
	CommitsWalked int    `json:"commitsWalked,omitempty"`
	CommitLimit   int    `json:"commitLimit,omitempty"`
}

type Collector struct {
	Name            string  `json:"name"`
	Status          string  `json:"status"` // completed | skipped | failed | partial
	Reason          string  `json:"reason,omitempty"`
	DurationSeconds float64 `json:"durationSeconds,omitempty"`
}

type Metric struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Unit       string `json:"unit,omitempty"`
	Statistic  string `json:"statistic,omitempty"`

	// any, because the schema allows number | string | boolean | null and an unmeasured
	// metric must stay null rather than collapsing to zero.
	Value any `json:"value"`

	Window         *MetricWindow   `json:"window,omitempty"`
	Classification *Classification `json:"classification,omitempty"`

	EvidenceSemantics    string `json:"evidenceSemantics"`
	EvidenceCompleteness string `json:"evidenceCompleteness"`
	PopulationSize       *int   `json:"populationSize,omitempty"`
	OmittedCount         int    `json:"omittedCount,omitempty"`
	TruncationReason     string `json:"truncationReason,omitempty"`

	EvidenceRefs []EvidenceRef `json:"evidenceRefs"`
	References   []Reference   `json:"references,omitempty"`
}

type MetricWindow struct {
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
	Label string `json:"label,omitempty"`
}

type Classification struct {
	Label      string `json:"label"`
	Thresholds string `json:"thresholds,omitempty"`
}

type Reference struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url"`
}

type EvidenceRef struct {
	Kind string `json:"kind"`

	RunIndex    *int `json:"runIndex,omitempty"`
	ResultIndex *int `json:"resultIndex,omitempty"`

	StatementIndex *int `json:"statementIndex,omitempty"`

	BomRef string `json:"bomRef,omitempty"`
	SpdxID string `json:"spdxId,omitempty"`

	Check       string `json:"check,omitempty"`
	DetailIndex *int   `json:"detailIndex,omitempty"`

	RecordID string `json:"recordId,omitempty"`
}

type Evidence struct {
	Records []any `json:"records,omitempty"`
}

type Attachments struct {
	SARIF     any `json:"sarif,omitempty"`
	OpenVEX   any `json:"openvex,omitempty"`
	CycloneDX any `json:"cyclonedx,omitempty"`
	SPDX      any `json:"spdx,omitempty"`
	Scorecard any `json:"scorecard,omitempty"`
}

type Diagnostic struct {
	Level     string `json:"level"` // error | warning | note
	Collector string `json:"collector,omitempty"`
	MetricID  string `json:"metricId,omitempty"`
	Message   string `json:"message"`
	Caveat    bool   `json:"caveat,omitempty"`
}

// ─── Graph ───────────────────────────────────────────────────────────────────────

type Graph struct {
	Nodes          []Node           `json:"nodes,omitempty"`
	Edges          []Edge           `json:"edges,omitempty"`
	CrossRepoEdges []CrossRepoEdge  `json:"crossRepoEdges,omitempty"`
	Truncation     *GraphTruncation `json:"truncation,omitempty"`
}

type GraphTruncation struct {
	NodesOmitted int    `json:"nodesOmitted,omitempty"`
	EdgesOmitted int    `json:"edgesOmitted,omitempty"`
	FilesSkipped int    `json:"filesSkipped,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type Node struct {
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	QualifiedName string         `json:"qualifiedName,omitempty"`
	Path          string         `json:"path,omitempty"`
	StartLine     int            `json:"startLine,omitempty"`
	EndLine       int            `json:"endLine,omitempty"`
	Language      string         `json:"language,omitempty"`
	Purl          string         `json:"purl,omitempty"`
	Exported      bool           `json:"exported,omitempty"`
	Properties    map[string]any `json:"properties,omitempty"`
}

type Edge struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	From        string         `json:"from"`
	To          string         `json:"to"`
	Confidence  float64        `json:"confidence,omitempty"`
	Resolution  string         `json:"resolution,omitempty"`
	EvidenceRef *EvidenceRef   `json:"evidenceRef,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// CrossRepoEdge is a declared intent to join, not a resolved edge. The scanner never reads
// another repository — it publishes a normalised key and says whether this repo provides it
// or consumes it. The org graph forms server-side where one repo's provides meets another's
// consumes. This is the whole reason a single-repo scan can build an org-wide graph.
type CrossRepoEdge struct {
	ID             string         `json:"id"`
	LocalNodeID    string         `json:"localNodeId"`
	JoinKind       string         `json:"joinKind"`
	JoinKey        string         `json:"joinKey"`
	Role           string         `json:"role"` // provides | consumes
	TargetRepoHint string         `json:"targetRepoHint,omitempty"`
	Confidence     float64        `json:"confidence,omitempty"`
	EvidenceRef    *EvidenceRef   `json:"evidenceRef,omitempty"`
	Properties     map[string]any `json:"properties,omitempty"`
}

// ─── Evidence records ────────────────────────────────────────────────────────────

type Identity struct {
	Name        string       `json:"name,omitempty"`
	Email       string       `json:"email,omitempty"`
	Login       string       `json:"login,omitempty"`
	CanonicalID string       `json:"canonicalId,omitempty"`
	IsBot       bool         `json:"isBot,omitempty"`
	BotKind     string       `json:"botKind,omitempty"`
	BotRule     string       `json:"botRule,omitempty"`
	EmailKind   string       `json:"emailKind,omitempty"`
	Affiliation *Affiliation `json:"affiliation,omitempty"`
}

type Affiliation struct {
	Company    string `json:"company,omitempty"`
	ValidFrom  string `json:"validFrom,omitempty"`
	ValidUntil string `json:"validUntil,omitempty"`
	Source     string `json:"source,omitempty"`
}

type CommitRecord struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"` // "commit"
	SHA         string     `json:"sha"`
	URL         string     `json:"url,omitempty"`
	Message     string     `json:"message,omitempty"`
	AuthoredAt  string     `json:"authoredAt,omitempty"`
	CommittedAt string     `json:"committedAt"`
	Author      *Identity  `json:"author,omitempty"`
	Committer   *Identity  `json:"committer,omitempty"`
	CoAuthors   []Identity `json:"coAuthors,omitempty"`
	ParentCount int        `json:"parentCount,omitempty"`
	Signature   *Signature `json:"signature,omitempty"`

	FilesChanged     int      `json:"filesChanged,omitempty"`
	Insertions       int      `json:"insertions,omitempty"`
	Deletions        int      `json:"deletions,omitempty"`
	Paths            []string `json:"paths,omitempty"`
	CycleTimeSeconds *int     `json:"cycleTimeSeconds,omitempty"`
}

type Signature struct {
	Signed       bool   `json:"signed,omitempty"`
	Verification string `json:"verification,omitempty"`
}

type ContributorRecord struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"` // "contributor"
	Identity *Identity `json:"identity"`
	Aliases  []Alias   `json:"aliases,omitempty"`

	FirstSeenAt string `json:"firstSeenAt,omitempty"`
	LastSeenAt  string `json:"lastSeenAt,omitempty"`

	Commits         int    `json:"commits,omitempty"`
	CommitsInWindow int    `json:"commitsInWindow,omitempty"`
	Insertions      int    `json:"insertions,omitempty"`
	Deletions       int    `json:"deletions,omitempty"`
	FilesTouched    int    `json:"filesTouched,omitempty"`
	TenureSeconds   *int   `json:"tenureSeconds,omitempty"`
	Status          string `json:"status,omitempty"`
}

type Alias struct {
	Identity   Identity `json:"identity"`
	MergedBy   string   `json:"mergedBy"`
	Confidence float64  `json:"confidence,omitempty"`
}

type FileRecord struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "file"
	Path string `json:"path"`

	Language string   `json:"language,omitempty"`
	Tags     []string `json:"tags,omitempty"`

	SizeBytes  *int `json:"sizeBytes,omitempty"`
	Lines      *int `json:"lines,omitempty"`
	Code       *int `json:"code,omitempty"`
	Comments   *int `json:"comments,omitempty"`
	Blanks     *int `json:"blanks,omitempty"`
	Complexity *int `json:"complexity,omitempty"`
	Binary     bool `json:"binary,omitempty"`

	Commits       int    `json:"commits,omitempty"`
	Authors       int    `json:"authors,omitempty"`
	FirstSeenAt   string `json:"firstSeenAt,omitempty"`
	LastChangedAt string `json:"lastChangedAt,omitempty"`

	Ownership *Ownership `json:"ownership,omitempty"`
}

type Ownership struct {
	TopAuthor       *Identity `json:"topAuthor,omitempty"`
	TopAuthorShare  float64   `json:"topAuthorShare,omitempty"`
	DistinctAuthors int       `json:"distinctAuthors,omitempty"`
}

type DependencyRecord struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "dependency"
	Purl string `json:"purl"`

	BomRef        string `json:"bomRef,omitempty"`
	Ecosystem     string `json:"ecosystem,omitempty"`
	ManifestPath  string `json:"manifestPath,omitempty"`
	Scope         string `json:"scope,omitempty"`
	DiscoveredVia string `json:"discoveredVia,omitempty"`

	DeclaredVersion string `json:"declaredVersion,omitempty"`
	ResolvedVersion string `json:"resolvedVersion,omitempty"`
	LatestVersion   string `json:"latestVersion,omitempty"`
	VersionsBehind  *int   `json:"versionsBehind,omitempty"`
	PublishedAt     string `json:"publishedAt,omitempty"`
	AgeSeconds      *int   `json:"ageSeconds,omitempty"`
	EOL             bool   `json:"eol,omitempty"`
	AdvisoryCount   int    `json:"advisoryCount,omitempty"`
}

// Durations are always integer seconds. issue-metrics emits `"6 days, 7:08:52"` in its JSON,
// which no consumer can do arithmetic on without writing a parser for a format that exists
// nowhere else.
type Durations struct {
	TimeToFirstResponseSeconds *int           `json:"timeToFirstResponseSeconds,omitempty"`
	TimeToFirstReviewSeconds   *int           `json:"timeToFirstReviewSeconds,omitempty"`
	TimeToCloseSeconds         *int           `json:"timeToCloseSeconds,omitempty"`
	TimeToMergeSeconds         *int           `json:"timeToMergeSeconds,omitempty"`
	TimeToAnswerSeconds        *int           `json:"timeToAnswerSeconds,omitempty"`
	TimeInLabelSeconds         map[string]int `json:"timeInLabelSeconds,omitempty"`

	// OpenEnded marks a duration measured against "now" because the item is still open. Such
	// a value grows between runs and must not be compared across reports as though it were
	// settled.
	OpenEnded bool `json:"openEnded,omitempty"`
}

type PullRequestRecord struct {
	ID     string    `json:"id"`
	Type   string    `json:"type"` // "pull_request"
	URL    string    `json:"url"`
	Number int       `json:"number,omitempty"`
	Title  string    `json:"title,omitempty"`
	Author *Identity `json:"author,omitempty"`
	State  string    `json:"state,omitempty"`

	CreatedAt string `json:"createdAt"`

	// ReadyForReviewAt is the anchor every response and merge duration is measured from, so
	// that time a pull request spent in draft is not charged against its reviewers.
	ReadyForReviewAt string `json:"readyForReviewAt,omitempty"`
	FirstResponseAt  string `json:"firstResponseAt,omitempty"`
	FirstReviewAt    string `json:"firstReviewAt,omitempty"`
	ClosedAt         string `json:"closedAt,omitempty"`

	// MergedAt is set only if the pull request was actually merged. A pull request closed
	// without merging has ClosedAt and no MergedAt, and the two are never conflated.
	MergedAt string    `json:"mergedAt,omitempty"`
	MergedBy *Identity `json:"mergedBy,omitempty"`

	Additions    int `json:"additions,omitempty"`
	Deletions    int `json:"deletions,omitempty"`
	ChangedFiles int `json:"changedFiles,omitempty"`
	CommentCount int `json:"commentCount,omitempty"`

	// ReviewerCount counts distinct reviewers other than the author. A self-approval is not
	// review coverage.
	ReviewerCount int `json:"reviewerCount,omitempty"`

	// ApprovalStatus: approved | changes_requested | review_required | unknown. `unknown`
	// means no review could be resolved at all — distinct from `review_required`, which means
	// one was required and not given.
	ApprovalStatus string `json:"approvalStatus,omitempty"`

	TimeInDraftSeconds *int       `json:"timeInDraftSeconds,omitempty"`
	Durations          *Durations `json:"durations,omitempty"`
}

type IssueRecord struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // "issue"
	URL         string    `json:"url"`
	Number      int       `json:"number,omitempty"`
	Title       string    `json:"title,omitempty"`
	Author      *Identity `json:"author,omitempty"`
	State       string    `json:"state,omitempty"`
	StateReason string    `json:"stateReason,omitempty"`
	Labels      []string  `json:"labels,omitempty"`

	CreatedAt string `json:"createdAt"`
	ClosedAt  string `json:"closedAt,omitempty"`

	// FirstResponseAt is the first comment by somebody other than the author, excluding bots.
	// Empty means no such response exists — which is not a response time of zero.
	FirstResponseAt string `json:"firstResponseAt,omitempty"`
	AnsweredAt      string `json:"answeredAt,omitempty"`

	Durations *Durations `json:"durations,omitempty"`
}

type ReviewRecord struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"` // "review"
	PullRequestURL string    `json:"pullRequestUrl"`
	Reviewer       *Identity `json:"reviewer,omitempty"`
	State          string    `json:"state"`
	SubmittedAt    string    `json:"submittedAt"`
}

type BranchRecord struct {
	ID           string `json:"id"`
	Type         string `json:"type"` // "branch"
	Name         string `json:"name"`
	IsDefault    bool   `json:"isDefault,omitempty"`
	Merged       bool   `json:"merged,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	LastCommitAt string `json:"lastCommitAt,omitempty"`
	AgeSeconds   *int   `json:"ageSeconds,omitempty"`
}

type GraphElementRecord struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "graph_element"
	ElementID string `json:"elementId"`
	Element   string `json:"element,omitempty"` // node | edge | cross_repo_edge
}

// ─── Builder ─────────────────────────────────────────────────────────────────────

// Builder assembles a report and — this is the point of it — makes the evidence invariant
// impossible to break by accident.
//
// A collector never states a count. It hands over the evidence and the builder derives the
// number from it. There is no code path where a collector can say "23" and attach 22 things,
// because there is no code path where a collector says a number at all.
type Builder struct {
	report  Report
	records []any
	seen    map[string]bool

	// fileByPath indexes each file record by its path.
	//
	// A path is a file record's identity, not merely one of its fields. Two records for one path
	// are not two pieces of evidence; they are one piece of evidence counted twice, and two
	// metrics citing "the same file" through different record ids would each be pointing at half
	// of what is known about it. The store they land in agrees, and is unique on (run, path).
	fileByPath map[string]int
}

func NewBuilder(tool Tool, target Target, startedAt time.Time) *Builder {
	return &Builder{
		report: Report{
			SchemaVersion: SchemaVersion,
			Tool:          tool,
			Target:        target,
			Run:           RunMeta{StartedAt: startedAt.UTC().Format(time.RFC3339)},
			Metrics:       []Metric{},
		},
		seen:       map[string]bool{},
		fileByPath: map[string]int{},
	}
}

// AddFile stores a file record — or folds it into the record already held for that path — and
// returns a ref to whichever it is. Collectors use this rather than AddRecord for files: the file
// walker and the policy checks both have something to say about `LICENSE`, and they have to end up
// saying it about the same record.
func (b *Builder) AddFile(rec *FileRecord) EvidenceRef {
	if i, ok := b.fileByPath[rec.Path]; ok {
		held, _ := b.records[i].(*FileRecord)
		held.Tags = mergeTags(held.Tags, rec.Tags)

		return EvidenceRef{Kind: "record", RecordID: held.ID}
	}

	ref := b.AddRecord(rec.ID, rec)
	b.fileByPath[rec.Path] = len(b.records) - 1

	return ref
}

func mergeTags(into, from []string) []string {
	has := make(map[string]bool, len(into))
	for _, t := range into {
		has[t] = true
	}
	for _, t := range from {
		if !has[t] {
			has[t] = true
			into = append(into, t)
		}
	}

	return into
}

// AddRecord stores an evidence record and returns a ref to it. The record's id must be
// unique; a duplicate is a programming error, not a data condition, so it panics rather than
// silently overwriting evidence that something else is already pointing at.
func (b *Builder) AddRecord(id string, rec any) EvidenceRef {
	if b.seen[id] {
		panic(fmt.Sprintf("analyze: duplicate evidence record id %q", id))
	}
	b.seen[id] = true
	b.records = append(b.records, rec)

	return EvidenceRef{Kind: "record", RecordID: id}
}

// Count adds a metric whose value IS the number of evidence items. The caller cannot get the
// count wrong because the caller does not supply it.
func (b *Builder) Count(m Metric, refs []EvidenceRef) {
	m.Value = float64(len(refs))
	m.Unit = orDefault(m.Unit, "count")
	m.EvidenceSemantics = "instances"
	m.EvidenceCompleteness = "exhaustive"
	m.EvidenceRefs = refs
	b.add(m)
}

// CountTruncated adds a count metric that hit a cap. The total is present + omitted, and the
// reason is mandatory — a cap that was hit silently is the failure mode this whole format
// exists to prevent, so there is no way to express one.
func (b *Builder) CountTruncated(m Metric, refs []EvidenceRef, omitted int, reason string) {
	if omitted <= 0 || strings.TrimSpace(reason) == "" {
		panic("analyze: a truncated metric must declare how many items it omitted and why")
	}
	m.Value = float64(len(refs) + omitted)
	m.Unit = orDefault(m.Unit, "count")
	m.EvidenceSemantics = "instances"
	m.EvidenceCompleteness = "truncated"
	m.OmittedCount = omitted
	m.TruncationReason = reason
	m.EvidenceRefs = refs
	b.add(m)
}

// Statistic adds a metric that summarises a population — a median, a mean, a slope, a ratio.
// The evidence is the whole population it was computed over, because a statistic without its
// distribution is a number you cannot argue with.
func (b *Builder) Statistic(m Metric, value float64, refs []EvidenceRef) {
	n := len(refs)
	m.Value = value
	m.EvidenceSemantics = "population"
	m.EvidenceCompleteness = "exhaustive"
	m.PopulationSize = &n
	m.EvidenceRefs = refs
	b.add(m)
}

// Assertion adds a judgement — a boolean, a category — supported by evidence that has no
// countable relationship to it.
func (b *Builder) Assertion(m Metric, value any, refs []EvidenceRef) {
	m.Value = value
	m.EvidenceSemantics = "assertion"
	m.EvidenceCompleteness = "exhaustive"
	m.EvidenceRefs = refs
	b.add(m)
}

// Unmeasured records a metric that could not be computed, and why.
//
// This is the difference between "we found no unreviewed commits" and "we could not check
// whether commits were reviewed", and it is a difference every tool surveyed manages to lose.
// The value is null, never zero, and the reason lands in the diagnostics attached to that
// metric id.
func (b *Builder) Unmeasured(m Metric, reason string) {
	m.Value = nil
	m.EvidenceSemantics = "instances"
	m.EvidenceCompleteness = "exhaustive"
	m.EvidenceRefs = []EvidenceRef{}
	b.add(m)
	b.Diagnose(Diagnostic{Level: "warning", MetricID: m.ID, Message: reason})
}

func (b *Builder) add(m Metric) {
	if m.EvidenceRefs == nil {
		m.EvidenceRefs = []EvidenceRef{}
	}
	b.report.Metrics = append(b.report.Metrics, m)
}

// Has reports whether a metric has already been emitted. Used by a collector that partially
// succeeded, so the failure path can fill in what is missing without emitting anything twice.
func (b *Builder) Has(id string) bool {
	for _, m := range b.report.Metrics {
		if m.ID == id {
			return true
		}
	}

	return false
}

func (b *Builder) Diagnose(d Diagnostic) {
	b.report.Diagnostics = append(b.report.Diagnostics, d)
}

func (b *Builder) Collected(c Collector) {
	b.report.Run.Collectors = append(b.report.Run.Collectors, c)
}

func (b *Builder) SetGraph(g *Graph) { b.report.Graph = g }

func (b *Builder) SetWindow(w *Window) { b.report.Run.HistoryWindow = w }

func (b *Builder) SetSARIF(doc any) {
	if b.report.Attachments == nil {
		b.report.Attachments = &Attachments{}
	}
	b.report.Attachments.SARIF = doc
}

// SARIFRef points at result i of run 0 — the single run every analyze report emits.
func SARIFRef(resultIndex int) EvidenceRef {
	zero := 0

	return EvidenceRef{Kind: "sarif", RunIndex: &zero, ResultIndex: &resultIndex}
}

// Finish seals the report and validates it against the schema and the evidence invariant.
// Nothing is written or uploaded that has not been through this: a report we would reject on
// the way in is a report we must not produce on the way out.
func (b *Builder) Finish(completedAt time.Time) (*Report, []byte, error) {
	b.report.Run.CompletedAt = completedAt.UTC().Format(time.RFC3339)
	started, _ := time.Parse(time.RFC3339, b.report.Run.StartedAt)
	b.report.Run.DurationSeconds = completedAt.Sub(started).Seconds()

	if len(b.records) > 0 {
		b.report.Evidence = &Evidence{Records: b.records}
	}

	if err := checkRecordIdentity(b.records); err != nil {
		return nil, nil, err
	}

	body, err := json.MarshalIndent(b.report, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal report: %w", err)
	}
	if err := ValidateReport(body); err != nil {
		return nil, nil, fmt.Errorf("the report we built is not one we would accept: %w", err)
	}

	return &b.report, body, nil
}

// checkRecordIdentity refuses to emit a report whose records collide on an identity the store
// treats as unique — a file's path, a commit's sha.
//
// The evidence store rejects the whole submission for one such collision, so a report that
// contains one is a report that stores nothing: not the colliding record, not the other 8,000.
// A collector that mints a second record for a path another collector already described is
// making a modelling error, and it is one we can catch here rather than in a rolled-back
// transaction with the error swallowed on the far side of the network.
func checkRecordIdentity(records []any) error {
	paths := map[string]string{}
	shas := map[string]string{}

	for _, r := range records {
		switch rec := r.(type) {
		case *FileRecord:
			if first, dup := paths[rec.Path]; dup {
				return fmt.Errorf(
					"two file records describe %s (records %q and %q): a path identifies a file record, "+
						"so a collector that has more to say about a file must add to the existing record "+
						"(Builder.AddFile) rather than mint a second one", rec.Path, first, rec.ID)
			}
			paths[rec.Path] = rec.ID
		case *CommitRecord:
			if first, dup := shas[rec.SHA]; dup {
				return fmt.Errorf("two commit records describe %s (records %q and %q)", rec.SHA, first, rec.ID)
			}
			shas[rec.SHA] = rec.ID
		}
	}

	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}

	return s
}
