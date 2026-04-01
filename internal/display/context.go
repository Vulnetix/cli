package display

import (
	"context"

	"github.com/spf13/cobra"
)

type contextKey struct{}

// Context bundles display capabilities for a command.
type Context struct {
	Logger *Logger
	Term   *Terminal
	Mode   OutputMode
	Silent bool
}

// New creates a display context from mode and silent flag.
func New(mode OutputMode, silent bool) *Context {
	term := NewTerminal()
	return &Context{
		Logger: NewLogger(mode, silent, term),
		Term:   term,
		Mode:   mode,
		Silent: silent,
	}
}

// NewFromFlags creates a display context from string output flag and silent bool.
func NewFromFlags(output string, silent bool) *Context {
	mode := ModeText
	if output == "json" {
		mode = ModeJSON
	}
	return New(mode, silent)
}

// Attach stores the display context in a cobra command's context.
func (c *Context) Attach(cmd *cobra.Command) {
	ctx := context.WithValue(cmd.Context(), contextKey{}, c)
	cmd.SetContext(ctx)
}

// FromCommand retrieves the display context from a cobra command.
// Returns a default text-mode context if none was attached.
func FromCommand(cmd *cobra.Command) *Context {
	if cmd.Context() != nil {
		if dc, ok := cmd.Context().Value(contextKey{}).(*Context); ok {
			return dc
		}
	}
	return New(ModeText, false)
}

// IsJSON returns true if output mode is JSON.
func (c *Context) IsJSON() bool {
	return c.Mode == ModeJSON
}

// Render outputs data as JSON (in JSON mode) or calls the text renderer.
// The text renderer receives data and the context, and returns a string.
func (c *Context) Render(data interface{}, textFn func(data interface{}, ctx *Context) string) error {
	if c.IsJSON() {
		return c.Logger.ResultJSON(data)
	}
	result := textFn(data, c)
	if result != "" {
		c.Logger.Result(result)
	}
	return nil
}
