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
}
