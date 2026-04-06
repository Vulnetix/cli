package triage

// resolve.go – status mapping between GitHub native alert states and VEX statuses,
// plus helpers for applying a resolution via the GitHub API and persisting it to memory.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vulnetix/cli/internal/memory"
)

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

// ResolutionOption represents one selectable resolution action for an alert.
// It captures both what to tell GitHub and what to record in VEX/memory.
type ResolutionOption struct {
	// Label is the short display string shown in the TUI list.
	Label string
	// Description is a one-line human explanation shown beneath the label.
	Description string

	// GitHubState is the target GitHub alert state ("dismissed", "resolved", "").
	// Empty means "VEX only" – save to memory without touching the GitHub alert.
	GitHubState string
	// GitHubReason is the dismissal reason (Dependabot/CodeQL) or resolution
	// value (Secret Scanning).  Empty when GitHubState is "".
	GitHubReason string

	// VEXStatus is the OpenVEX / CycloneDX VEX status to persist in memory:
	//   not_affected | affected | fixed | under_investigation
	VEXStatus string
	// VEXJustification is the OpenVEX justification code (used only for
	// not_affected status):
	//   component_not_present | vulnerable_code_not_present |
	//   vulnerable_code_not_in_execute_path |
	//   vulnerable_code_cannot_be_controlled_by_adversary |
	//   inline_mitigations_already_exist
	VEXJustification string
}

// GitHubOnly returns true when this option produces a GitHub API call.
func (r ResolutionOption) GitHubOnly() bool { return r.GitHubState == "" }

// VEXBadge returns a short string showing the VEX status (and justification).
func (r ResolutionOption) VEXBadge() string {
	if r.VEXJustification != "" {
		return r.VEXStatus + " (" + r.VEXJustification + ")"
	}
	return r.VEXStatus
}

// OptionsForAlert returns the ordered list of resolution options appropriate
// for the alert's ecosystem / provider type.
func OptionsForAlert(a Alert) []ResolutionOption {
	switch a.Ecosystem {
	case "dependabot":
		return dependabotOptions()
	case "codeql":
		return codeqlOptions()
	case "secrets":
		return secretsOptions()
	default:
		// Unknown / future ecosystems: offer VEX-only statuses only.
		return vexOnlyOptions()
	}
}

func dependabotOptions() []ResolutionOption {
	return []ResolutionOption{
		{
			Label:            "[GH] Dismiss: Fix Started",
			Description:      "A fix has already been started",
			GitHubState:      "dismissed",
			GitHubReason:     "fix_started",
			VEXStatus:        "affected",
			VEXJustification: "",
		},
		{
			Label:            "[GH] Dismiss: No Bandwidth",
			Description:      "No bandwidth to fix this right now",
			GitHubState:      "dismissed",
			GitHubReason:     "no_bandwidth",
			VEXStatus:        "under_investigation",
			VEXJustification: "",
		},
		{
			Label:            "[GH] Dismiss: Inaccurate",
			Description:      "This alert is inaccurate or incorrect",
			GitHubState:      "dismissed",
			GitHubReason:     "inaccurate",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_cannot_be_controlled_by_adversary",
		},
		{
			Label:            "[GH] Dismiss: Not Used",
			Description:      "Vulnerable code is not actually used",
			GitHubState:      "dismissed",
			GitHubReason:     "not_used",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_present",
		},
		{
			Label:            "[GH] Dismiss: Tolerable Risk",
			Description:      "Risk is tolerable to this project",
			GitHubState:      "dismissed",
			GitHubReason:     "tolerable_risk",
			VEXStatus:        "not_affected",
			VEXJustification: "inline_mitigations_already_exist",
		},
		{
			Label:       "[VEX] Under Investigation",
			Description: "Save as under investigation (memory only)",
			GitHubState: "",
			VEXStatus:   "under_investigation",
		},
		{
			Label:       "[VEX] Mark Affected",
			Description: "Confirm this is exploitable in your environment (memory only)",
			GitHubState: "",
			VEXStatus:   "affected",
		},
		{
			Label:       "[VEX] Mark Fixed",
			Description: "Record that this has been remediated (memory only)",
			GitHubState: "",
			VEXStatus:   "fixed",
		},
	}
}

func codeqlOptions() []ResolutionOption {
	return []ResolutionOption{
		{
			Label:            "[GH] Dismiss: False Positive",
			Description:      "The finding is a false positive",
			GitHubState:      "dismissed",
			GitHubReason:     "false positive",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_present",
		},
		{
			Label:            "[GH] Dismiss: Won't Fix",
			Description:      "Acknowledged but will not be fixed",
			GitHubState:      "dismissed",
			GitHubReason:     "won't fix",
			VEXStatus:        "not_affected",
			VEXJustification: "inline_mitigations_already_exist",
		},
		{
			Label:            "[GH] Dismiss: Used in Tests",
			Description:      "The vulnerable code only runs in tests",
			GitHubState:      "dismissed",
			GitHubReason:     "used in tests",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_in_execute_path",
		},
		{
			Label:       "[VEX] Under Investigation",
			Description: "Save as under investigation (memory only)",
			GitHubState: "",
			VEXStatus:   "under_investigation",
		},
		{
			Label:       "[VEX] Mark Affected",
			Description: "Confirm this is a real exploitable finding (memory only)",
			GitHubState: "",
			VEXStatus:   "affected",
		},
		{
			Label:       "[VEX] Mark Fixed",
			Description: "Record that this code has been remediated (memory only)",
			GitHubState: "",
			VEXStatus:   "fixed",
		},
	}
}

func secretsOptions() []ResolutionOption {
	return []ResolutionOption{
		{
			Label:            "[GH] Resolve: Revoked",
			Description:      "Secret has been revoked / rotated",
			GitHubState:      "resolved",
			GitHubReason:     "revoked",
			VEXStatus:        "fixed",
			VEXJustification: "",
		},
		{
			Label:            "[GH] Resolve: False Positive",
			Description:      "This is not a real secret",
			GitHubState:      "resolved",
			GitHubReason:     "false_positive",
			VEXStatus:        "not_affected",
			VEXJustification: "component_not_present",
		},
		{
			Label:            "[GH] Resolve: Won't Fix",
			Description:      "Acknowledged but will not be rotated",
			GitHubState:      "resolved",
			GitHubReason:     "wont_fix",
			VEXStatus:        "not_affected",
			VEXJustification: "inline_mitigations_already_exist",
		},
		{
			Label:            "[GH] Resolve: Used in Tests",
			Description:      "Secret only appears in test fixtures",
			GitHubState:      "resolved",
			GitHubReason:     "used_in_tests",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_not_in_execute_path",
		},
		{
			Label:            "[GH] Resolve: Pattern Noisy",
			Description:      "The detection pattern generates too many false positives",
			GitHubState:      "resolved",
			GitHubReason:     "pattern_noisy",
			VEXStatus:        "not_affected",
			VEXJustification: "vulnerable_code_cannot_be_controlled_by_adversary",
		},
		{
			Label:       "[VEX] Under Investigation",
			Description: "Save as under investigation (memory only)",
			GitHubState: "",
			VEXStatus:   "under_investigation",
		},
	}
}

func vexOnlyOptions() []ResolutionOption {
	return []ResolutionOption{
		{Label: "[VEX] Not Affected", Description: "Component is not affected", VEXStatus: "not_affected"},
		{Label: "[VEX] Affected", Description: "Component is affected", VEXStatus: "affected"},
		{Label: "[VEX] Fixed", Description: "Remediation is in place", VEXStatus: "fixed"},
		{Label: "[VEX] Under Investigation", Description: "Under active investigation", VEXStatus: "under_investigation"},
	}
}

// ---------------------------------------------------------------------------
// GitHub API calls
// ---------------------------------------------------------------------------

// ApplyResolution sends a PATCH request to GitHub to update the alert state.
// If opt.GitHubState is empty (VEX-only option) the call is skipped.
func ApplyResolution(ctx context.Context, client *GitHubClient, repo string, a Alert, opt ResolutionOption, rationale string) error {
	if opt.GitHubState == "" {
		// VEX-only: nothing to send to GitHub.
		return nil
	}

	num, err := strconv.Atoi(a.Number)
	if err != nil {
		return fmt.Errorf("invalid alert number %q: %w", a.Number, err)
	}

	switch a.Ecosystem {
	case "dependabot":
		return client.PatchDependabotAlert(ctx, repo, num, opt.GitHubReason, rationale)
	case "codeql":
		return client.PatchCodeQLAlert(ctx, repo, num, opt.GitHubReason, rationale)
	case "secrets":
		return client.PatchSecretAlert(ctx, repo, num, opt.GitHubReason, rationale)
	default:
		return fmt.Errorf("GitHub update not supported for ecosystem %q", a.Ecosystem)
	}
}

// ---------------------------------------------------------------------------
// Memory persistence
// ---------------------------------------------------------------------------

// RecordResolutionInMemory persists the chosen resolution to .vulnetix/memory.yaml.
func RecordResolutionInMemory(vulnetixDir string, a Alert, opt ResolutionOption, rationale string) error {
	if err := os.MkdirAll(vulnetixDir, 0o755); err != nil {
		return fmt.Errorf("create vulnetix dir: %w", err)
	}

	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		mem = &memory.Memory{Version: "1"}
	}

	// Determine the canonical key: prefer CVE, then RuleID, then #Number.
	key := a.CVE
	if key == "" {
		key = a.RuleID
	}
	if key == "" {
		key = "#" + a.Number
	}

	now := time.Now().UTC().Format(time.RFC3339)

	existing := mem.GetFinding(key)
	var rec memory.FindingRecord
	if existing != nil {
		rec = *existing
	}

	rec.Status = opt.VEXStatus
	rec.Justification = opt.VEXJustification
	rec.ActionResponse = rationale
	rec.Package = a.Package
	rec.Ecosystem = a.Ecosystem
	if rec.Severity == "" {
		rec.Severity = a.Severity
	}
	rec.Source = "github-triage"

	rec.Decision = &memory.Decision{
		Choice: opt.Label,
		Reason: rationale,
		Date:   now,
	}

	rec.History = append(rec.History, memory.HistoryEntry{
		Date:  now,
		Event: "resolve",
		Detail: fmt.Sprintf("status=%s label=%q gh_state=%q gh_reason=%q",
			opt.VEXStatus, opt.Label, opt.GitHubState, opt.GitHubReason),
	})

	mem.SetFinding(key, rec)

	return memory.Save(vulnetixDir, mem)
}

// ---------------------------------------------------------------------------
// GitHubClient PATCH helpers (added to ghclient.go package via this file)
// ---------------------------------------------------------------------------

// PatchDependabotAlert dismisses a Dependabot alert.
// reason must be one of: fix_started, no_bandwidth, inaccurate, not_used, tolerable_risk
func (c *GitHubClient) PatchDependabotAlert(ctx context.Context, repo string, alertNumber int, reason, comment string) error {
	body := map[string]string{
		"state":             "dismissed",
		"dismissed_reason":  reason,
		"dismissed_comment": comment,
	}
	return c.patchAlert(ctx, fmt.Sprintf("/repos/%s/dependabot/alerts/%d", repo, alertNumber), body)
}

// PatchCodeQLAlert dismisses a Code Scanning (CodeQL) alert.
// reason must be one of: false positive, won't fix, used in tests
func (c *GitHubClient) PatchCodeQLAlert(ctx context.Context, repo string, alertNumber int, reason, comment string) error {
	body := map[string]string{
		"state":             "dismissed",
		"dismissed_reason":  reason,
		"dismissed_comment": comment,
	}
	return c.patchAlert(ctx, fmt.Sprintf("/repos/%s/code-scanning/alerts/%d", repo, alertNumber), body)
}

// PatchSecretAlert resolves a Secret Scanning alert.
// resolution must be one of: false_positive, wont_fix, revoked, used_in_tests, pattern_noisy, pattern_deleted
func (c *GitHubClient) PatchSecretAlert(ctx context.Context, repo string, alertNumber int, resolution, comment string) error {
	body := map[string]string{
		"state":              "resolved",
		"resolution":         resolution,
		"resolution_comment": comment,
	}
	return c.patchAlert(ctx, fmt.Sprintf("/repos/%s/secret-scanning/alerts/%d", repo, alertNumber), body)
}

// patchAlert is the shared low-level PATCH helper.
func (c *GitHubClient) patchAlert(ctx context.Context, path string, body interface{}) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal patch body: %w", err)
	}

	url := c.resolveURL(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Message != "" {
			return fmt.Errorf("GitHub API PATCH %s returned %d: %s", path, resp.StatusCode, errBody.Message)
		}
		return fmt.Errorf("GitHub API PATCH %s returned %d", path, resp.StatusCode)
	}

	return nil
}

// DefaultVulnetixDir returns the .vulnetix directory relative to the current
// working directory, matching the convention used by scan and other commands.
func DefaultVulnetixDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ".vulnetix"
	}
	return filepath.Join(cwd, ".vulnetix")
}
