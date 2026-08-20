package cmd

import (
	"errors"
	"fmt"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────
// exit_codes_test.go — the error→exit-code mapping.
//
// This is the one place a mistake silently turns a red gate green, so every
// case is pinned, including the ones that assert nothing changed for the
// commands that existed before jail did.
// ─────────────────────────────────────────────────────────────────────────

func TestExitCodeMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil is success", nil, ExitOK},
		{"a plain error exits 1", errors.New("boom"), ExitFailure},

		// These two pin that the pre-existing gates did NOT move. Every pipeline
		// in the field treats a quality-gate breach as exit 1; changing that
		// would be a breaking change to somebody's CI.
		{"quality gate breach still exits 1", &MultiPolicyBreachError{}, ExitFailure},
		{"licence severity breach still exits 1", &SeverityBreachError{}, ExitFailure},

		{"jail breach exits 1", &JailVerdictError{Verdict: "jailed", Code: ExitFailure}, ExitFailure},
		{"jail indeterminate exits 3", &JailVerdictError{Verdict: "indeterminate", Code: ExitIndeterminate}, ExitIndeterminate},
		{"jail usage error exits 2", &JailUsageError{err: errors.New("bad flag")}, ExitUsage},

		// A zero code must not be honoured: an error that claims exit 0 is a
		// bug, and reporting success for it would be the worst possible outcome.
		{"a zero code falls back to 1", &JailVerdictError{Verdict: "jailed", Code: 0}, ExitFailure},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.err); got != tc.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestExitCodeSurvivesWrapping is the case that catches the demotion bug.
//
// ExitCode uses errors.As rather than a bare type assertion. Under an assertion,
// any `fmt.Errorf("...: %w", err)` anywhere in a call chain would make the check
// miss and quietly return 1 — and a demoted 3 reads to a pipeline as an ordinary
// build failure rather than "the gate could not tell", which is the entire
// distinction the code exists to carry.
func TestExitCodeSurvivesWrapping(t *testing.T) {
	inner := &JailVerdictError{Verdict: "indeterminate", Code: ExitIndeterminate}

	once := fmt.Errorf("wrapped: %w", inner)
	if got := ExitCode(once); got != ExitIndeterminate {
		t.Fatalf("ExitCode(wrapped once) = %d, want %d", got, ExitIndeterminate)
	}

	twice := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", inner))
	if got := ExitCode(twice); got != ExitIndeterminate {
		t.Fatalf("ExitCode(wrapped twice) = %d, want %d", got, ExitIndeterminate)
	}

	usage := fmt.Errorf("context: %w", &JailUsageError{err: errors.New("bad")})
	if got := ExitCode(usage); got != ExitUsage {
		t.Fatalf("ExitCode(wrapped usage) = %d, want %d", got, ExitUsage)
	}
}

// TestJailUsageErrorUnwraps pins that the cause stays reachable, so a caller can
// still inspect it rather than only reading the message.
func TestJailUsageErrorUnwraps(t *testing.T) {
	cause := errors.New("the actual problem")
	err := &JailUsageError{err: cause}
	if !errors.Is(err, cause) {
		t.Fatal("JailUsageError does not unwrap to its cause")
	}
}

// TestIsJailVerdictError pins the predicate Execute() uses to suppress the
// redundant "Error:" line, including through a wrapper.
func TestIsJailVerdictError(t *testing.T) {
	if !isJailVerdictError(&JailVerdictError{Code: 1}) {
		t.Fatal("a jail verdict was not recognised")
	}
	if !isJailVerdictError(fmt.Errorf("wrapped: %w", &JailVerdictError{Code: 3})) {
		t.Fatal("a wrapped jail verdict was not recognised")
	}
	// A usage failure renders nothing of its own, so it must keep the prefix.
	if isJailVerdictError(&JailUsageError{err: errors.New("x")}) {
		t.Fatal("a usage error was mistaken for a verdict and would lose its Error: prefix")
	}
	if isJailVerdictError(errors.New("unrelated")) {
		t.Fatal("an unrelated error was mistaken for a verdict")
	}
}
