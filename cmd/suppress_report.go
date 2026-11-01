package cmd

import (
	"strings"
	"sync"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/sast"
	"github.com/vulnetix/cli/v3/internal/suppress"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Local suppression reporting. Every finding an ignore rule or a nosec comment
// hides before upload is recorded here, and the list rides cli.finalize as
// localSuppressions so the server can say which rule hid which finding. VEX
// statements from --vex-file are not rules and are never recorded here.

// lastSCAScannerRunUuid is the run uuid of this scan's SCA snapshot, when the
// server sent one. Reset per run with lastContainerSnapshotUuid.
var lastSCAScannerRunUuid string

var (
	localSuppressionsMu   sync.Mutex
	localSuppressionsList []vdb.CliLocalSuppression
	localSuppressionsSeen = map[vdb.CliLocalSuppression]bool{}
)

// resetLocalSuppressions starts a new run's list.
func resetLocalSuppressions() {
	localSuppressionsMu.Lock()
	defer localSuppressionsMu.Unlock()
	localSuppressionsList = nil
	localSuppressionsSeen = map[vdb.CliLocalSuppression]bool{}
}

// recordLocalSuppression adds one hidden finding, taking the rule's identity
// (uuid, source, type, reason) from the rule that matched. A rule with no uuid
// is still recorded: the server skips it, and the list stays a true account of
// what this run hid.
func recordLocalSuppression(r suppress.Rule, s vdb.CliLocalSuppression) {
	s.RuleUUID = r.UUID
	s.Source = r.Source
	if s.Source == "" {
		s.Source = suppress.SourceMemory
	}
	s.Type = r.Type
	s.Reason = r.Reason
	if s.Category == "" {
		s.Category = r.Category
	}
	addLocalSuppression(s)
}

func addLocalSuppression(s vdb.CliLocalSuppression) {
	localSuppressionsMu.Lock()
	defer localSuppressionsMu.Unlock()
	if localSuppressionsSeen[s] {
		return
	}
	localSuppressionsSeen[s] = true
	localSuppressionsList = append(localSuppressionsList, s)
}

// recordNosecHits records the findings inline nosec comments hid. The rule
// uuid comes from memory.yaml when an earlier scan already synced the comment
// to the server (same identity as reconcileScanSuppressions uses).
func recordNosecHits(mem *memory.Memory, git *gitctx.GitContext, hits []sast.NosecHit) {
	repo := ""
	if git != nil {
		repo = suppress.RepoFullName(git.RemoteURLs)
	}
	for _, h := range hits {
		s := vdb.CliLocalSuppression{
			Source:   suppress.SourceNosec,
			Category: kindToCategory(h.Kind),
			RuleID:   h.RuleID,
			FilePath: h.File,
			Line:     h.StartLine,
			Type:     "nosec",
			Reason:   "inline nosec directive",
		}
		if mem != nil {
			if existing := findSuppression(mem, memory.SuppressionRecord{
				Origin: "nosec", RuleID: h.RuleID, RepositoryFullName: repo, Snippet: h.Snippet,
			}); existing != nil {
				s.RuleUUID = existing.UUID
				if strings.TrimSpace(existing.Reason) != "" {
					s.Reason = existing.Reason
				}
			}
		}
		addLocalSuppression(s)
	}
}

// localSuppressionsForFinalize is this run's list, sent with every finalize.
// The server resolves each entry against the snapshot it finalizes, so an
// entry for another snapshot's category matches nothing there.
func localSuppressionsForFinalize() []vdb.CliLocalSuppression {
	localSuppressionsMu.Lock()
	defer localSuppressionsMu.Unlock()
	if len(localSuppressionsList) == 0 {
		return nil
	}
	return append([]vdb.CliLocalSuppression(nil), localSuppressionsList...)
}
