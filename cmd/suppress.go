package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/suppress"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// validSuppressionTypes is the shared vocabulary (kept in sync with the website
// src/shared/suppression.ts and the backend). rego_rule/nosec are machine
// sources; the rest are human triage outcomes.
var validSuppressionTypes = map[string]bool{
	"false_positive": true,
	"wont_fix":       true,
	"risk_accepted":  true,
	"mitigated":      true,
	"deferred":       true,
	"rego_rule":      true,
	"nosec":          true,
}

// suppressCmd — `vulnetix ignore` (alias `suppress`): manage "ignore" rules that
// persist as Suppression records (backend + .vulnetix/memory.yaml) and filter
// scanner findings before report output.
var suppressCmd = &cobra.Command{
	Use:     "ignore",
	Aliases: []string{"suppress"},
	Short:   "Manage suppression ('ignore') rules for scanner findings",
	Long: `Manage suppression rules that filter scanner findings before report output.

Rules are anchored by a rego rule id (the rego file id), a finding id
(CVE/vuln id), an inventory component value (--value: an algorithm/SPDX id,
certificate subject, model id or purl) or a file path — optionally narrowed to
a line. They are persisted both locally in .vulnetix/memory.yaml and — when
authenticated — in the Vulnetix backend so the whole organisation shares them.

Beyond the scanner families, --category crypto and --category ai skip matching
components during 'vulnetix cbom' and 'vulnetix aibom'; an ignored AI component
is also never shown in the Vulnetix console.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Credentials optional: local memory.yaml still works offline.
		return resolveVDBCredentials(false)
	},
}

var suppressAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a suppression rule",
	RunE:  runSuppressAdd,
}

var suppressListCmd = &cobra.Command{
	Use:   "list",
	Short: "List suppression rules (local + remote)",
	RunE:  runSuppressList,
}

var suppressRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Deactivate a suppression rule",
	RunE:  runSuppressRemove,
}

var suppressSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Pull remote suppression rules into .vulnetix/memory.yaml",
	RunE:  runSuppressSync,
}

func suppressResolveDir(cmd *cobra.Command) (rootPath, vulnetixDir string, git *gitctx.GitContext) {
	rootPath, _ = cmd.Flags().GetString("path")
	if rootPath == "" {
		rootPath = "."
	}
	if abs, err := filepath.Abs(rootPath); err == nil {
		rootPath = abs
	}
	vulnetixDir = filepath.Join(rootPath, ".vulnetix")
	git = gitctx.Collect(rootPath)
	return rootPath, vulnetixDir, git
}

func runSuppressAdd(cmd *cobra.Command, _ []string) error {
	_, vulnetixDir, git := suppressResolveDir(cmd)

	ruleID, _ := cmd.Flags().GetString("rule")
	findingID, _ := cmd.Flags().GetString("finding")
	targetValue, _ := cmd.Flags().GetString("value")
	filePath, _ := cmd.Flags().GetString("file")
	category, _ := cmd.Flags().GetString("category")
	sType, _ := cmd.Flags().GetString("type")
	reason, _ := cmd.Flags().GetString("reason")
	lineRange, _ := cmd.Flags().GetString("line-range")
	lineNumber, _ := cmd.Flags().GetInt("line")
	expiresIn, _ := cmd.Flags().GetInt("expires-in")

	if strings.TrimSpace(ruleID) == "" && strings.TrimSpace(findingID) == "" &&
		strings.TrimSpace(targetValue) == "" && strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("one of --rule, --finding, --value or --file is required")
	}
	// A bare --line is not an anchor of its own: without a file it would narrow
	// nothing, and silently ignoring it would look like it had taken effect.
	if lineNumber > 0 && strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("--line needs --file: a line number only narrows a file anchor")
	}
	if lineNumber > 0 && strings.TrimSpace(lineRange) == "" {
		lineRange = strconv.Itoa(lineNumber)
	}
	if sType == "" {
		if ruleID != "" {
			sType = "rego_rule"
		} else {
			sType = "risk_accepted"
		}
	}
	if !validSuppressionTypes[sType] {
		return fmt.Errorf("--type %q is not valid (one of false_positive, wont_fix, risk_accepted, mitigated, deferred, rego_rule, nosec)", sType)
	}

	repoFullName := ""
	branch := ""
	if git != nil {
		repoFullName = suppress.RepoFullName(git.RemoteURLs)
		branch = git.CurrentBranch
	}

	now := time.Now().Unix()
	var expiresAt int64
	if expiresIn > 0 {
		expiresAt = now + int64(expiresIn)*86400
	}

	rec := memory.SuppressionRecord{
		RuleID:             ruleID,
		Category:           category,
		Type:               sType,
		Reason:             reason,
		FindingID:          findingID,
		TargetValue:        targetValue,
		FilePath:           filePath,
		LineNumber:         lineNumber,
		LineRange:          lineRange,
		RepositoryFullName: repoFullName,
		Branch:             branch,
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
		IsActive:           true,
		Origin:             "cli",
	}

	// Push to the backend first (best-effort) so we can persist the server uuid.
	if client := newCliClient(); client != nil {
		resp, err := client.CliSuppressionsSet(envForCliWithGit(git), toSetRequest(rec, expiresIn))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not save rule to Vulnetix backend (%v); saved locally only\n", err)
		} else if resp != nil {
			if sup, ok := resp.Data["suppression"].(map[string]any); ok {
				if id, _ := sup["uuid"].(string); id != "" {
					rec.UUID = id
				}
			}
		}
	}

	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		return err
	}
	mem.UpsertSuppression(rec)
	if err := memory.Save(vulnetixDir, mem); err != nil {
		return err
	}

	fmt.Printf("Suppression rule added (%s).\n", suppressAnchorLabel(rec))
	return nil
}

func toSetRequest(rec memory.SuppressionRecord, ignoreDays int) vdb.CliSuppressionSetRequest {
	return vdb.CliSuppressionSetRequest{
		Action:             "create",
		RuleID:             suppressAnchorID(rec),
		Category:           rec.Category,
		SuppressionType:    rec.Type,
		Reason:             rec.Reason,
		TargetValue:        rec.TargetValue,
		FilePath:           rec.FilePath,
		LineNumber:         rec.LineNumber,
		LineRange:          rec.LineRange,
		RepositoryFullName: rec.RepositoryFullName,
		BranchName:         rec.Branch,
		IgnoreDays:         ignoreDays,
	}
}

func runSuppressList(cmd *cobra.Command, _ []string) error {
	_, vulnetixDir, git := suppressResolveDir(cmd)
	now := time.Now().Unix()

	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		return err
	}

	// The uuid is printed because it is the only handle `ignore remove` accepts
	// for a rule with no rego-rule or finding anchor — an inventory rule was
	// otherwise impossible to remove from the CLI at all.
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tACTIVE\tTYPE\tCATEGORY\tANCHOR\tFILE\tREASON\tUUID")
	for _, s := range mem.Suppressions {
		fmt.Fprintf(tw, "local\t%v\t%s\t%s\t%s\t%s\t%s\t%s\n",
			s.IsActive && (s.ExpiresAt == 0 || s.ExpiresAt > now), s.Type, suppressCategoryLabel(s.Category), suppressKeyLabel(s.RuleID, s.FindingID, s.TargetValue), s.FilePath, suppTruncate(s.Reason, 40), s.UUID)
	}

	if client := newCliClient(); client != nil {
		req := vdb.CliSuppressionsGetRequest{ActiveOnly: false}
		if git != nil {
			req.RepositoryFullName = suppress.RepoFullName(git.RemoteURLs)
		}
		if resp, err := client.CliSuppressionsGet(envForCliWithGit(git), req); err == nil && resp != nil {
			for _, s := range resp.Data.Suppressions {
				fmt.Fprintf(tw, "remote\t%v\t%s\t%s\t%s\t%s\t%s\t%s\n",
					s.IsActive, s.SuppressionType, suppressCategoryLabel(s.Category), suppressKeyLabel(s.RuleID, s.FindingUUID, s.TargetValue), s.FilePath, suppTruncate(s.Reason, 40), s.UUID)
			}
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fetch remote rules (%v)\n", err)
		}
	}
	return tw.Flush()
}

func runSuppressRemove(cmd *cobra.Command, _ []string) error {
	_, vulnetixDir, git := suppressResolveDir(cmd)
	uuid, _ := cmd.Flags().GetString("uuid")
	ruleID, _ := cmd.Flags().GetString("rule")
	findingID, _ := cmd.Flags().GetString("finding")
	targetValue, _ := cmd.Flags().GetString("value")
	anchorID := ruleID
	if anchorID == "" {
		anchorID = findingID
	}
	if anchorID == "" {
		// An inventory rule has neither a rego rule id nor a CVE, so --value is
		// the handle it was created with and the one it must be removable by.
		anchorID = targetValue
	}
	if uuid == "" && anchorID == "" {
		return fmt.Errorf("--uuid, --rule, --finding or --value is required")
	}
	repoFullName := ""
	if git != nil {
		repoFullName = suppress.RepoFullName(git.RemoteURLs)
	}

	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		return err
	}
	// Capture the server uuids before deactivating: the remote endpoint keys on
	// uuid or ruleId, and an inventory rule has no ruleId — without the uuids
	// the local rule would go quiet while the org-wide one stayed in force.
	remoteUUIDs := mem.MatchingSuppressionUUIDs(uuid, anchorID, repoFullName)
	n := mem.DeactivateSuppression(uuid, anchorID, repoFullName)
	if err := memory.Save(vulnetixDir, mem); err != nil {
		return err
	}

	if client := newCliClient(); client != nil {
		reason, _ := cmd.Flags().GetString("reason")
		if len(remoteUUIDs) == 0 {
			remoteUUIDs = []string{uuid}
		}
		for _, id := range remoteUUIDs {
			_, err := client.CliSuppressionsSet(envForCliWithGit(git), vdb.CliSuppressionSetRequest{
				Action:             "deactivate",
				UUID:               id,
				RuleID:             anchorID,
				RepositoryFullName: repoFullName,
				DeactivatedReason:  reason,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not deactivate remotely (%v)\n", err)
			}
		}
	}
	fmt.Printf("Deactivated %d local rule(s).\n", n)
	return nil
}

func runSuppressSync(cmd *cobra.Command, _ []string) error {
	_, vulnetixDir, git := suppressResolveDir(cmd)
	client := newCliClient()
	if client == nil {
		return fmt.Errorf("authentication required to sync remote rules")
	}
	req := vdb.CliSuppressionsGetRequest{ActiveOnly: false}
	if git != nil {
		req.RepositoryFullName = suppress.RepoFullName(git.RemoteURLs)
	}
	resp, err := client.CliSuppressionsGet(envForCliWithGit(git), req)
	if err != nil {
		return fmt.Errorf("fetch remote rules: %w", err)
	}
	remote := resp.Data.Suppressions

	mem, err := memory.Load(vulnetixDir)
	if err != nil {
		return err
	}
	for _, s := range remote {
		mem.UpsertSuppression(memory.SuppressionRecord{
			UUID:               s.UUID,
			RuleID:             s.RuleID,
			Category:           s.Category,
			Type:               s.SuppressionType,
			Reason:             s.Reason,
			TargetValue:        s.TargetValue,
			FilePath:           s.FilePath,
			LineNumber:         s.LineNumber,
			LineRange:          s.LineRange,
			RepositoryFullName: s.RepositoryFullName,
			Branch:             s.BranchName,
			CreatedAt:          s.CreatedAt,
			ExpiresAt:          s.ExpiresAt,
			IsActive:           s.IsActive,
		})
	}
	if err := memory.Save(vulnetixDir, mem); err != nil {
		return err
	}
	fmt.Printf("Synced %d remote rule(s) into %s.\n", len(remote), filepath.Join(vulnetixDir, "memory.yaml"))
	return nil
}

// suppressCategoryLabel renders a rule's category for the `ignore list` table.
// An uncategorised rule matches on its other anchors alone, which is worth
// showing as such rather than as blank space.
func suppressCategoryLabel(category string) string {
	if category == "" {
		return "any"
	}
	return category
}

// suppressKeyLabel names the anchor a rule is written against, for the `ignore
// list` table. Inventory rules (crypto/ai) carry neither a rego rule id nor a
// finding id, so without the value arm every one of them listed as "—" and the
// table could not tell them apart.
func suppressKeyLabel(ruleID, findingID, targetValue string) string {
	if ruleID != "" {
		return ruleID
	}
	if findingID != "" {
		return findingID
	}
	if targetValue != "" {
		return targetValue
	}
	return "—"
}

// suppressAnchorID is the id the server anchors a suppression to. There is one
// field on the wire (`ruleId`) and two locally: a rego rule id for SAST-style
// rules and a CVE for SCA/license/malware ones. Both are matched server-side
// against Finding.findingId, which holds whichever of the two that finding
// carries — so a finding-anchored rule must travel in the same field. Sending
// only RuleID left a `--finding CVE-…` rule on the server with no anchor at
// all, which suppressed nothing and listed with an em dash where its id belongs.
func suppressAnchorID(rec memory.SuppressionRecord) string {
	if rec.RuleID != "" {
		return rec.RuleID
	}
	return rec.FindingID
}

func suppressAnchorLabel(rec memory.SuppressionRecord) string {
	switch {
	case rec.RuleID != "":
		return "rule " + rec.RuleID
	case rec.FindingID != "":
		return "finding " + rec.FindingID
	case rec.TargetValue != "":
		return "value " + rec.TargetValue
	default:
		return "file " + rec.FilePath
	}
}

func suppTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	for _, c := range []*cobra.Command{suppressAddCmd, suppressListCmd, suppressRemoveCmd, suppressSyncCmd} {
		c.Flags().String("path", ".", "Repository path to scope the rule to")
	}
	suppressAddCmd.Flags().String("rule", "", "Rego rule id to suppress (the rego file id)")
	suppressAddCmd.Flags().String("finding", "", "Finding id (CVE/vuln id) to suppress")
	suppressAddCmd.Flags().String("value", "", "Inventory component value to ignore (algorithm/SPDX id, certificate subject, model id or purl)")
	suppressAddCmd.Flags().String("file", "", "File path to suppress findings in")
	suppressAddCmd.Flags().String("category", "", "Scanner category (sast|secrets|iac|container|sca|license|malware|crypto|ai)")
	suppressAddCmd.Flags().String("type", "", "Suppression type (false_positive|wont_fix|risk_accepted|mitigated|deferred|rego_rule|nosec)")
	suppressAddCmd.Flags().String("reason", "", "Human-readable reason")
	suppressAddCmd.Flags().String("line-range", "", "Line range within the file (e.g. 10-14)")
	suppressAddCmd.Flags().Int("line", 0, "Single line within the file to narrow the rule to (requires --file)")
	suppressAddCmd.Flags().Int("expires-in", 0, "Auto-expire the rule after N days (0 = never)")

	suppressRemoveCmd.Flags().String("uuid", "", "Suppression uuid to deactivate")
	suppressRemoveCmd.Flags().String("rule", "", "Deactivate rules matching this rego rule id")
	suppressRemoveCmd.Flags().String("finding", "", "Deactivate rules matching this finding id (CVE/vuln id)")
	suppressRemoveCmd.Flags().String("value", "", "Deactivate inventory rules matching this component value")
	suppressRemoveCmd.Flags().String("reason", "", "Reason for deactivation")

	suppressCmd.AddCommand(suppressAddCmd, suppressListCmd, suppressRemoveCmd, suppressSyncCmd)
	rootCmd.AddCommand(suppressCmd)
}
