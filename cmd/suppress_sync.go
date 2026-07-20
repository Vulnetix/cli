package cmd

// Scan-time suppression reconciliation.
//
// A SAST-family scan owns the lifecycle of code-anchored suppressions:
//   1. nosec directives discovered this run are folded into memory.yaml
//      (Origin=nosec) — identity is (rule + snippet), so re-detecting a moved
//      comment updates the existing record's file/line instead of duplicating.
//   2. Existing snippet-anchored rules that were NOT re-detected are relocated
//      via git-blame following (internal/suppressdrift); a rule whose snippet is
//      gone from the tree is auto-deactivated.
//   3. The reconciled set becomes []vdb.CliSuppressionMint, attached to the
//      SARIF upload so the backend upserts org Suppression rows.
// applyMintedSuppressionUUIDs writes server-returned uuids back onto the local
// records so future scans update by uuid.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/suppress"
	"github.com/vulnetix/cli/v3/internal/suppressdrift"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// reconcileScanSuppressions folds this scan's nosec hits into memory, drift-
// tracks existing snippet-anchored rules, and returns the mint list to send to
// the backend. It mutates mem in place; the caller persists via memory.Save.
func reconcileScanSuppressions(mem *memory.Memory, gitCtx *gitctx.GitContext, nosecHits []sast.NosecHit, rootPath string, now int64) []vdb.CliSuppressionMint {
	if mem == nil {
		return nil
	}
	repoFullName := ""
	branch := ""
	commit := ""
	if gitCtx != nil {
		repoFullName = suppress.RepoFullName(gitCtx.RemoteURLs)
		branch = gitCtx.CurrentBranch
		commit = gitCtx.CurrentCommit
	}

	// 1) Fold nosec hits. Track which record identities were refreshed so we can
	//    skip re-drifting them and detect nosec comments that vanished.
	refreshed := map[string]bool{}
	for _, h := range nosecHits {
		rec := memory.SuppressionRecord{
			RuleID:             h.RuleID,
			Category:           kindToCategory(h.Kind),
			Type:               "nosec",
			Reason:             "inline nosec directive",
			FilePath:           h.File,
			LineNumber:         h.StartLine,
			LineRange:          lineRange(h.StartLine, h.EndLine),
			Snippet:            h.Snippet,
			RepositoryFullName: repoFullName,
			Branch:             branch,
			CreatedAt:          now,
			IsActive:           true,
			LastSeenCommit:     commit,
			LastSeenAt:         now,
			Origin:             "nosec",
		}
		// Preserve uuid/created_at of an existing identical rule.
		if existing := findSuppression(mem, rec); existing != nil {
			rec.UUID = existing.UUID
			if existing.CreatedAt > 0 {
				rec.CreatedAt = existing.CreatedAt
			}
		}
		mem.UpsertSuppression(rec)
		refreshed[suppressionFingerprint(rec)] = true
	}

	// 2) Drift-track active snippet-anchored rules not refreshed above.
	var anchors []suppressdrift.Anchor
	anchorFP := map[string]string{} // anchor.Key -> fingerprint
	for _, s := range mem.Suppressions {
		if !s.IsActive || s.Snippet == "" {
			continue
		}
		fp := suppressionFingerprint(s)
		if refreshed[fp] {
			continue
		}
		anchors = append(anchors, suppressdrift.Anchor{
			Key:        fp,
			FilePath:   s.FilePath,
			LineNumber: firstLine(s),
			Snippet:    s.Snippet,
		})
		anchorFP[fp] = fp
	}
	if len(anchors) > 0 && rootPath != "" {
		if results, err := suppressdrift.Reconcile(rootPath, anchors); err == nil {
			byKey := make(map[string]suppressdrift.Result, len(results))
			for _, r := range results {
				byKey[r.Key] = r
			}
			for i := range mem.Suppressions {
				s := &mem.Suppressions[i]
				if !s.IsActive || s.Snippet == "" {
					continue
				}
				r, ok := byKey[suppressionFingerprint(*s)]
				if !ok {
					continue
				}
				if r.Gone {
					s.IsActive = false
					if s.Reason == "" || s.Type == "nosec" {
						s.Reason = "anchor removed"
					}
					continue
				}
				if r.Moved {
					s.FilePath = r.FilePath
					s.LineNumber = r.Line
					s.LineRange = lineRange(r.Line, r.Line)
				}
				s.LastSeenAt = now
				if r.Commit != "" {
					s.LastSeenCommit = r.Commit
				} else if commit != "" {
					s.LastSeenCommit = commit
				}
			}
		}
	}

	// 3) Build the mint list from every touched (active or just-deactivated) rule
	//    that is code-anchored (has a snippet), scoped to this repo.
	var mints []vdb.CliSuppressionMint
	for _, s := range mem.Suppressions {
		if s.Snippet == "" {
			continue // only sync code-anchored rules from a scan
		}
		if repoFullName != "" && s.RepositoryFullName != "" && s.RepositoryFullName != repoFullName {
			continue
		}
		m := vdb.CliSuppressionMint{
			UUID:            s.UUID,
			RuleID:          s.RuleID,
			Category:        s.Category,
			SuppressionType: s.Type,
			Reason:          s.Reason,
			FilePath:        s.FilePath,
			LineNumber:      s.LineNumber,
			LineRange:       s.LineRange,
			CodeSnippet:     s.Snippet,
			BranchName:      s.Branch,
			Origin:          s.Origin,
			Active:          s.IsActive,
			Fingerprint:     suppressionFingerprint(s),
		}
		if !s.IsActive {
			m.DeactivatedReason = s.Reason
		}
		mints = append(mints, m)
	}
	return mints
}

// applyMintedSuppressionUUIDs writes each server-returned uuid onto the local
// record with the matching fingerprint.
func applyMintedSuppressionUUIDs(mem *memory.Memory, results []vdb.CliSuppressionResult) bool {
	if mem == nil || len(results) == 0 {
		return false
	}
	byFP := make(map[string]string, len(results))
	for _, r := range results {
		if r.Fingerprint != "" && r.UUID != "" {
			byFP[r.Fingerprint] = r.UUID
		}
	}
	changed := false
	for i := range mem.Suppressions {
		s := &mem.Suppressions[i]
		if s.UUID != "" {
			continue
		}
		if uuid, ok := byFP[suppressionFingerprint(*s)]; ok {
			s.UUID = uuid
			changed = true
		}
	}
	return changed
}

// suppressionFingerprint is a stable, drift-invariant key: it deliberately
// excludes file path and line number (which move) and keys on origin + rule +
// repo + the pinned snippet.
func suppressionFingerprint(s memory.SuppressionRecord) string {
	h := sha256.Sum256([]byte(strings.ToLower(s.Origin) + "\x00" +
		strings.ToLower(s.RuleID) + "\x00" +
		s.RepositoryFullName + "\x00" +
		strings.TrimSpace(s.Snippet)))
	return hex.EncodeToString(h[:])[:32]
}

func findSuppression(mem *memory.Memory, rec memory.SuppressionRecord) *memory.SuppressionRecord {
	target := suppressionFingerprint(rec)
	for i := range mem.Suppressions {
		if suppressionFingerprint(mem.Suppressions[i]) == target {
			return &mem.Suppressions[i]
		}
	}
	return nil
}

func firstLine(s memory.SuppressionRecord) int {
	if s.LineNumber > 0 {
		return s.LineNumber
	}
	// Fall back to the start of a "start-end" LineRange.
	if s.LineRange != "" {
		var a int
		if _, err := fmt.Sscanf(s.LineRange, "%d", &a); err == nil {
			return a
		}
	}
	return 0
}

func lineRange(start, end int) string {
	if start <= 0 {
		return ""
	}
	if end <= start {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}
