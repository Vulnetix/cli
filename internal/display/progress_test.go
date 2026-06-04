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
