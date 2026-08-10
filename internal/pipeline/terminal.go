package pipeline

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vulnetix/cli/v3/internal/display"
)

// TerminalReporter drives the existing display.Progress activity: one live
// line on stderr, with log output routed through Progress.Writer so a log line
// clears and redraws the progress row instead of leaving duplicates behind.
//
// This is the reporter the CLI uses, and it reproduces exactly what
// cmd/runLocalScan did inline before the extraction. The language server
// installs a different implementation that turns the same calls into
// $/progress notifications.
type TerminalReporter struct {
	baseReporter
	progress *display.Progress
	out      io.Writer
}

// NewTerminalReporter starts a progress activity titled `title` with `total`
// numbered steps, rendering to stderr.
//
// The arguments mirror the CLI's own flags: silent suppresses everything,
// noProgress keeps log output but drops the live line. Both are honoured by
// display.Progress itself, so a disabled progress activity is a safe no-op
// rather than a nil that every call site has to check.
func NewTerminalReporter(title string, total int, silent, noProgress bool) *TerminalReporter {
	dctx := display.NewWithProgress(display.ModeText, silent, noProgress)
	progress := dctx.Progress(title, total)
	return &TerminalReporter{
		progress: progress,
		out:      progress.Writer(os.Stderr),
	}
}

// NewTerminalReporterFrom wraps an already-started progress activity. Use it
// when the caller owns the display context, for instance because it renders
// results through the same context after the analysis finishes.
func NewTerminalReporterFrom(progress *display.Progress) *TerminalReporter {
	return &TerminalReporter{
		progress: progress,
		out:      progress.Writer(os.Stderr),
	}
}

func (r *TerminalReporter) Stage(stage string) { r.progress.SetStage(stage) }

func (r *TerminalReporter) Update(done int, stage string) { r.progress.Update(done, stage) }

func (r *TerminalReporter) Logf(level Level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch level {
	case LevelInfo:
		fmt.Fprintf(r.out, "%s\n", msg)
	default:
		// Matches the "  warning: ..." shape the scan output already used, so
		// the extraction is not visible in the terminal.
		fmt.Fprintf(r.out, "  %s: %s\n", level, msg)
	}
}

func (r *TerminalReporter) Degraded(note string) {
	r.addDegradation(note)
	if strings.TrimSpace(note) != "" {
		fmt.Fprintf(r.out, "  %s\n", note)
	}
}

func (r *TerminalReporter) Degradations() []string { return r.snapshotDegradations() }

func (r *TerminalReporter) Complete(stage string) {
	if r.claimFinish() {
		r.progress.Complete(stage)
	}
}

func (r *TerminalReporter) Fail(stage string) {
	if r.claimFinish() {
		r.progress.Fail(stage)
	}
}

func (r *TerminalReporter) Writer() io.Writer { return r.out }

// Progress exposes the underlying activity for the few call sites that still
// need it directly. Kept narrow on purpose: everything reachable through
// Reporter should go through Reporter.
func (r *TerminalReporter) Progress() *display.Progress { return r.progress }
