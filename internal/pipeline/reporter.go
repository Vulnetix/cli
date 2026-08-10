// Package pipeline is the owner of "run an analysis".
//
// Both the CLI's scan family and the language server reach analysis through
// this package, which is what AGENTS.md means by "every capability has exactly
// one owner, reached through one options-struct entry function". Before this
// package existed, the analysis lived in cmd/runLocalScan: 1,600 lines, 40
// positional parameters, and hard-wired to a terminal.
//
// Reporter is the seam that made the extraction possible. The analysis emits
// progress and diagnostics through this interface instead of writing to a
// terminal, so the same code path can drive a spinner on stderr, an LSP
// $/progress token, or nothing at all in a test.
package pipeline

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Level classifies a Reporter log line. It maps onto LSP MessageType
// (1=Error, 2=Warning, 3=Info) without translation.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelWarn:
		return "warning"
	case LevelError:
		return "error"
	case LevelInfo:
		return "info"
	default:
		return "info"
	}
}

// Reporter receives progress, log output and degradation notices from an
// analysis run.
//
// Implementations must be safe for concurrent use: the scan stages fan out
// across goroutines, and the language server evaluates shards in parallel.
//
// A nil Reporter is not valid; use Discard() when output is not wanted.
type Reporter interface {
	// Stage changes the current stage label without changing numeric progress.
	Stage(stage string)

	// Update sets numeric progress out of the total declared at construction,
	// and, when stage is non-empty, the stage label with it.
	Update(done int, stage string)

	// Logf writes one diagnostic line. Callers must not append a newline.
	Logf(level Level, format string, args ...any)

	// Degraded records that part of the analysis did not run to completion:
	// files skipped over the size cap, git history unavailable, a stage that
	// failed without failing the run. These are collected and surfaced, because
	// "no findings" and "did not look" must not be indistinguishable.
	Degraded(note string)

	// Degradations returns everything passed to Degraded, in order.
	Degradations() []string

	// Complete and Fail finalise the run exactly once. Subsequent calls are
	// ignored, so a deferred Complete after an early Fail is harmless.
	Complete(stage string)
	Fail(stage string)

	// Writer is the transitional escape hatch for callees that still take an
	// io.Writer directly (sast.LoadAllModules, autofix.RunInstall,
	// postScanSARIF). Everything written to it is ordinary log output. New code
	// should use Logf; this exists so the extraction could land without also
	// rewriting every callee's signature in the same change.
	Writer() io.Writer
}

// baseReporter provides the degradation ledger and the finish-once guard that
// every implementation needs.
type baseReporter struct {
	mu           sync.Mutex
	degradations []string
	finished     bool
}

func (b *baseReporter) addDegradation(note string) {
	note = strings.TrimSpace(note)
	if note == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.degradations = append(b.degradations, note)
}

func (b *baseReporter) snapshotDegradations() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.degradations) == 0 {
		return nil
	}
	out := make([]string, len(b.degradations))
	copy(out, b.degradations)
	return out
}

// claimFinish reports whether this call is the first to finish the run.
func (b *baseReporter) claimFinish() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.finished {
		return false
	}
	b.finished = true
	return true
}

// discardReporter drops everything except degradations, which stay observable
// because tests assert on them.
type discardReporter struct {
	baseReporter
}

// Discard returns a Reporter that produces no output. Use it for --silent runs
// and in tests that do not assert on progress.
func Discard() Reporter { return &discardReporter{} }

func (r *discardReporter) Stage(string)               {}
func (r *discardReporter) Update(int, string)         {}
func (r *discardReporter) Logf(Level, string, ...any) {}
func (r *discardReporter) Degraded(note string)       { r.addDegradation(note) }
func (r *discardReporter) Degradations() []string     { return r.snapshotDegradations() }
func (r *discardReporter) Complete(string)            { r.claimFinish() }
func (r *discardReporter) Fail(string)                { r.claimFinish() }
func (r *discardReporter) Writer() io.Writer          { return io.Discard }

// WriterReporter writes plain lines to w and keeps a degradation ledger. It is
// the implementation used by tests that want to assert on output, and by any
// caller that has a writer but no terminal.
type WriterReporter struct {
	baseReporter
	w io.Writer
}

// NewWriterReporter returns a Reporter writing to w. A nil w discards.
func NewWriterReporter(w io.Writer) *WriterReporter {
	if w == nil {
		w = io.Discard
	}
	return &WriterReporter{w: w}
}

func (r *WriterReporter) Stage(stage string) {
	if stage = strings.TrimSpace(stage); stage != "" {
		fmt.Fprintf(r.w, "%s\n", stage)
	}
}

func (r *WriterReporter) Update(_ int, stage string) { r.Stage(stage) }

func (r *WriterReporter) Logf(level Level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if level == LevelInfo {
		fmt.Fprintf(r.w, "%s\n", msg)
		return
	}
	fmt.Fprintf(r.w, "%s: %s\n", level, msg)
}

func (r *WriterReporter) Degraded(note string) {
	r.addDegradation(note)
	r.Logf(LevelWarn, "%s", note)
}

func (r *WriterReporter) Degradations() []string { return r.snapshotDegradations() }

func (r *WriterReporter) Complete(stage string) {
	if r.claimFinish() && strings.TrimSpace(stage) != "" {
		fmt.Fprintf(r.w, "%s\n", stage)
	}
}

func (r *WriterReporter) Fail(stage string) {
	if r.claimFinish() && strings.TrimSpace(stage) != "" {
		fmt.Fprintf(r.w, "%s\n", stage)
	}
}

func (r *WriterReporter) Writer() io.Writer { return r.w }
