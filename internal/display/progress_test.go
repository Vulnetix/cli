package display

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/muesli/termenv"
)

func TestProgressWriterClearsAndRedrawsInteractiveLine(t *testing.T) {
	p := &Progress{
		enabled:     true,
		interactive: true,
		term:        &Terminal{ColorProfile: termenv.Ascii},
		title:       "Scan",
		stage:       "Loading SAST rules",
		done:        4,
		total:       7,
	}

	var buf bytes.Buffer
	n, err := fmt.Fprint(p.Writer(&buf), "Imported 256 rules\n")
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len("Imported 256 rules\n") {
		t.Fatalf("expected write count %d, got %d", len("Imported 256 rules\n"), n)
	}

	got := buf.String()
	if strings.Count(got, "\r\033[2K") != 2 {
		t.Fatalf("expected clear before log and redraw after log, got %q", got)
	}
	if !strings.Contains(got, "Imported 256 rules\n") {
		t.Fatalf("expected log line in output, got %q", got)
	}
	if !strings.Contains(got, "-  Scan") || !strings.Contains(got, "4/7 (57%)") || !strings.Contains(got, "Loading SAST rules") {
		t.Fatalf("expected progress line to be redrawn, got %q", got)
	}
}

func TestProgressWriterPassesThroughWhenNotInteractive(t *testing.T) {
	p := &Progress{
		enabled:     true,
		interactive: false,
	}

	var buf bytes.Buffer
	_, err := fmt.Fprint(p.Writer(&buf), "plain log\n")
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if got := buf.String(); got != "plain log\n" {
		t.Fatalf("expected plain output, got %q", got)
	}
}

// Vulnetix/cli#177: fix asked "Choose manifest to fix [0]:" while the scan's
// spinner was live, and the spinner's next redraw ("\r\033[2K") erased the
// question, so a waiting stdin read looked like a hang. While suspended, the
// row is cleared once and neither the ticker nor a log line redraws it.
func TestProgressSuspendHoldsTheRowUntilResumed(t *testing.T) {
	p := &Progress{
		enabled:     true,
		interactive: true,
		term:        &Terminal{ColorProfile: termenv.Ascii},
		title:       "Scan",
		done:        4,
		total:       7,
		stop:        make(chan struct{}),
		donec:       make(chan struct{}),
	}
	resume := p.Suspend()
	if !p.isSuspended() {
		t.Fatal("not suspended")
	}

	var buf bytes.Buffer
	fmt.Fprint(p.Writer(&buf), "Choose manifest to fix [0]: ")
	if strings.Contains(buf.String(), "Scan") {
		t.Fatalf("progress row redrawn over a prompt: %q", buf.String())
	}

	// A nested suspend keeps it held until both are released.
	inner := p.Suspend()
	resume()
	resume() // idempotent
	if !p.isSuspended() {
		t.Fatal("released by the outer resume while an inner suspend is open")
	}
	inner()
	if p.isSuspended() {
		t.Fatal("still suspended after every resume")
	}
}

func TestProgressSuspendIsANoOpWhenNotInteractive(t *testing.T) {
	p := &Progress{enabled: true, interactive: false}
	resume := p.Suspend()
	resume()
	if p.isSuspended() {
		t.Fatal("a non-interactive progress has no row to hold")
	}
	var nilP *Progress
	nilP.Suspend()()
}
