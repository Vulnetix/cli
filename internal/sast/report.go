package sast

// SASTReport holds the results of a SAST evaluation run.
type SASTReport struct {
	Findings    []Finding
	Rules       []RuleMetadata
	RulesLoaded int
}
