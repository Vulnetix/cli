package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Event is a hook lifecycle event.
//
// Only the events this package answers are named. A host that fires something
// else gets an empty response rather than an error: an unrecognised event is
// not a failure, it is an event with nothing to say about it.
type Event string

const (
	EventPreToolUse       Event = "PreToolUse"
	EventPostToolUse      Event = "PostToolUse"
	EventUserPromptSubmit Event = "UserPromptSubmit"
	EventSessionStart     Event = "SessionStart"
	EventStop             Event = "Stop"
)

// Payload is what a host sends on stdin.
//
// The field set is the intersection of what Claude Code and Codex send, which
// covers everything this package reads. Both also send extras the other does
// not — Codex adds model and turn_id, Claude adds prompt_id and effort — and
// none of them change a verdict, so they are not decoded.
type Payload struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	HookEventName  Event           `json:"hook_event_name"`
	PermissionMode string          `json:"permission_mode"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
	// UserInput carries the prompt on UserPromptSubmit. Hosts disagree on the
	// key, so both spellings are accepted.
	UserInput string `json:"user_input"`
	Prompt    string `json:"prompt"`
}

// BashInput is the tool_input shape for a shell call.
type BashInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// EditInput is the tool_input shape for a file write. Hosts spell the path key
// differently across their Edit and Write tools, so every spelling is decoded
// and the first non-empty one wins.
type EditInput struct {
	FilePath  string `json:"file_path"`
	Path      string `json:"path"`
	OldString string `json:"old_string"`
	NewString string `json:"new_string"`
	Content   string `json:"content"`
}

// TargetPath returns the file an edit would touch.
func (e EditInput) TargetPath() string {
	if e.FilePath != "" {
		return e.FilePath
	}
	return e.Path
}

// Command returns the shell command a Bash tool call would run, or empty when
// this payload is not a shell call.
func (p Payload) Command() string {
	if len(p.ToolInput) == 0 {
		return ""
	}
	var in BashInput
	if err := json.Unmarshal(p.ToolInput, &in); err != nil {
		return ""
	}
	return in.Command
}

// EditTarget returns the path a file-writing tool call would touch, or empty.
func (p Payload) EditTarget() string {
	if len(p.ToolInput) == 0 {
		return ""
	}
	var in EditInput
	if err := json.Unmarshal(p.ToolInput, &in); err != nil {
		return ""
	}
	return in.TargetPath()
}

// UserPrompt returns the submitted prompt, whichever key the host used.
func (p Payload) UserPrompt() string {
	if p.UserInput != "" {
		return p.UserInput
	}
	return p.Prompt
}

// Decision is what the hook concluded.
type Decision int

const (
	// Silent says nothing at all. This is the correct outcome whenever the
	// repository's own policy is satisfied, and it is the outcome the guard
	// reaches most often.
	Silent Decision = iota
	// Inform adds what the hook knows to the model's context without
	// interrupting.
	Inform
	// Block refuses the tool call and tells the model why.
	Block
)

// Response is the hook's answer, before it is encoded for a host.
type Response struct {
	Event    Event
	Decision Decision
	// Message is the text the model receives, as context on Inform and as the
	// refusal reason on Block.
	Message string
}

// hookSpecificOutput is the wire shape both hosts accept.
//
// PermissionDecision is omitted entirely on Inform. This is not a style
// preference: Codex fails the hook outright on `"permissionDecision":"allow"`,
// while both hosts deliver additionalContext to the model when the field is
// absent. Omitting it is also the more honest description of what the hook is
// doing, which is adding what it knows rather than granting permission.
type hookSpecificOutput struct {
	HookEventName            Event  `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string `json:"additionalContext,omitempty"`
}

type hookEnvelope struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

// Encode writes the response in the form both Claude Code and Codex accept.
//
// A Silent decision writes nothing. An empty stdout is the documented way to
// say "no opinion", and it is what keeps the guard liveable: a hook that prints
// on every install is one people turn off.
func (r Response) Encode(w io.Writer) error {
	if r.Decision == Silent || strings.TrimSpace(r.Message) == "" {
		return nil
	}

	out := hookSpecificOutput{HookEventName: r.Event}
	switch r.Decision {
	case Block:
		out.PermissionDecision = "deny"
		out.PermissionDecisionReason = r.Message
	case Inform:
		out.AdditionalContext = r.Message
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(hookEnvelope{HookSpecificOutput: out}); err != nil {
		return fmt.Errorf("encoding hook response: %w", err)
	}
	return nil
}

// DecodePayload reads a host's hook payload.
//
// A payload that cannot be parsed is not an error the hook should surface. The
// host is mid-tool-call and the only useful thing to do is stand aside, so the
// caller treats a decode failure as Silent.
func DecodePayload(r io.Reader) (Payload, error) {
	var p Payload
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("decoding hook payload: %w", err)
	}
	return p, nil
}
