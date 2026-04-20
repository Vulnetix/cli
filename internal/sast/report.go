package sast

// SASTReport holds the results of a SAST evaluation run.
type SASTReport struct {
	Findings    []Finding
	Rules       []RuleMetadata
	RulesLoaded int // rules after filtering (kind/id) that were evaluated
	RulesTotal  int // rules loaded pre-filter (builtin + --rule repos)
}
