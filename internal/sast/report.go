package sast

// SASTReport holds the results of a SAST evaluation run.
type SASTReport struct {
	Findings    []Finding
	Rules       []RuleMetadata
	RulesLoaded int // rules after filtering (kind/id) that were evaluated
	RulesTotal  int // rules loaded pre-filter (builtin + --rule repos)
	// Degradations lists capabilities that ran reduced or not at all during
	// this evaluation ("couldn't verify X because Y"). They are surfaced as
	// SARIF toolExecutionNotifications so a report consumer can distinguish
	// "scanned clean" from "not fully scanned".
	Degradations []string
	// CachedFiles were served from the result cache for the per-file rules;
	// EvaluatedFiles were evaluated by them. Both are 0 without a cache.
	CachedFiles    int
	EvaluatedFiles int
	// CachedGroups were scope groups whose other rules (whole-tree rules, and
	// per-file rules that read the file list) were served from the result
	// cache; EvaluatedGroups were evaluated. Both are 0 without a cache.
	CachedGroups    int
	EvaluatedGroups int
}
