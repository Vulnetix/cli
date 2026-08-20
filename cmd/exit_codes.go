package cmd

import "errors"

// ─────────────────────────────────────────────────────────────────────────
// exit_codes.go — mapping an error returned by Execute onto a process exit code.
//
// Until the jail gate landed the CLI had exactly one failure code: every error
// exited 1. That is still the default and every existing command keeps it. What
// this file adds is a way for a command to say "this particular failure means
// something else", which the jail gate needs so a pipeline can tell
//
//	1  you breached policy            — a fact about the code
//	3  the gate could not be evaluated — a fact about the pipeline
//
// apart. Those two demand different escalation: one is fixed by a developer,
// the other by whoever owns the CI configuration.
// ─────────────────────────────────────────────────────────────────────────

// Process exit codes. These are a contract with every pipeline in the field;
// changing what one means is a breaking change to somebody's CI.
const (
	// ExitOK — the command succeeded.
	ExitOK = 0
	// ExitFailure — the command failed, or a policy gate breached. Every error
	// that does not name its own code lands here, which is what the CLI did
	// before this file existed.
	ExitFailure = 1
	// ExitUsage — a local argument or configuration error, before any
	// meaningful work was attempted.
	ExitUsage = 2
	// ExitIndeterminate — the gate ran but could not reach a verdict, because
	// the backend state it needs is stale or absent. NOT a pass and NOT a
	// breach.
	ExitIndeterminate = 3
)

// ExitCodeError is an error that names the process exit code it should produce.
//
// Absent this interface an error still exits 1, which is what every command in
// the tree did before jail existed and must keep doing.
type ExitCodeError interface {
	error
	ExitCode() int
}

// ExitCode resolves the process exit code for an error returned by Execute.
//
// errors.As, not a bare type assertion. A future `fmt.Errorf("...: %w", err)`
// wrapper anywhere in a call chain would make an assertion miss, silently
// demoting a 3 to a 1 — and a demoted 3 reads to a pipeline as an ordinary
// build failure rather than "the gate could not tell". That is the whole
// distinction this file exists to preserve, so it is asserted in
// exit_codes_test.go.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ec ExitCodeError
	if errors.As(err, &ec) {
		if code := ec.ExitCode(); code > 0 {
			return code
		}
	}
	return ExitFailure
}
