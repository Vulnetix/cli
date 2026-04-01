package display

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// OutputMode determines how output is routed.
type OutputMode int

const (
	ModeText OutputMode = iota
	ModeJSON
)

// Logger routes output between stdout and stderr based on mode and silent flags.
type Logger struct {
	mode   OutputMode
	silent bool
	term   *Terminal
}

// NewLogger creates a logger with the given mode and silent flag.
func NewLogger(mode OutputMode, silent bool, term *Terminal) *Logger {
	return &Logger{mode: mode, silent: silent, term: term}
}

// Info prints an informational message to stderr. Suppressed when silent.
func (l *Logger) Info(msg string) {
	if l.silent {
		return
	}
	msg = l.cleanMessage(msg)
	fmt.Fprintln(os.Stderr, msg)
}

// Infof prints a formatted informational message to stderr.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Info(fmt.Sprintf(format, args...))
}

// Status prints a status/progress message to stderr. Suppressed when silent.
func (l *Logger) Status(msg string) {
	if l.silent {
		return
	}
	msg = l.cleanMessage(msg)
	fmt.Fprintln(os.Stderr, msg)
}

// Statusf prints a formatted status message to stderr.
func (l *Logger) Statusf(format string, args ...interface{}) {
	l.Status(fmt.Sprintf(format, args...))
}

// Warn prints a warning to stderr. Suppressed when silent.
func (l *Logger) Warn(msg string) {
	if l.silent {
		return
	}
	msg = l.cleanMessage(msg)
	if !l.term.StderrTTY {
		msg = "[WARN] " + msg
	}
	fmt.Fprintln(os.Stderr, msg)
}

// Warnf prints a formatted warning to stderr.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Warn(fmt.Sprintf(format, args...))
}

// Error prints an error to stderr. Never suppressed.
func (l *Logger) Error(msg string) {
	msg = l.cleanMessage(msg)
	if !l.term.StderrTTY {
		msg = "[ERR] " + msg
	}
	fmt.Fprintln(os.Stderr, msg)
}

// Errorf prints a formatted error to stderr.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Error(fmt.Sprintf(format, args...))
}

// Result prints the final text result to stdout.
func (l *Logger) Result(s string) {
	fmt.Println(s)
}

// ResultJSON encodes data as indented JSON to stdout.
func (l *Logger) ResultJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// cleanMessage strips emoji when not a TTY.
func (l *Logger) cleanMessage(msg string) string {
	if l.term.StderrTTY {
		return msg
	}
	return stripEmoji(msg)
}

// stripEmoji removes common emoji characters and trims leading whitespace that remains.
func stripEmoji(s string) string {
	var b strings.Builder
	for _, r := range s {
		// Skip common emoji ranges
		if r >= 0x1F300 && r <= 0x1FAFF {
			continue
		}
		if r >= 0x2600 && r <= 0x27BF {
			continue
		}
		if r >= 0xFE00 && r <= 0xFE0F {
			continue
		}
		if r >= 0x200D && r <= 0x200D {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimLeft(b.String(), " ")
}
