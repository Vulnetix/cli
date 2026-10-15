package check

type Outcome string

const (
	OutcomePass    Outcome = "pass"
	OutcomeFail    Outcome = "fail"
	StageTestPass          = "test"
	ModeBypass             = "default"
	CompilerPass           = "root"
)

var results = map[string]Outcome{"lint": OutcomePass}
