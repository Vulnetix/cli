package memory

import "strings"

// UpsertSuppression inserts or replaces a suppression by UUID (when set) or by
// the RuleID+RepositoryFullName anchor. Returns true if an existing record was
// replaced rather than appended.
func (m *Memory) UpsertSuppression(rec SuppressionRecord) bool {
	for i, s := range m.Suppressions {
		if suppressionSameIdentity(s, rec) {
			m.Suppressions[i] = rec
			return true
		}
	}
	m.Suppressions = append(m.Suppressions, rec)
	return false
}

// DeactivateSuppression flips IsActive=false on the first matching record.
// Matches by UUID when set, else by RuleID (+RepositoryFullName when given).
// Returns the number of records deactivated.
// anchorID matches either anchor a rule can carry: a rego rule id or a finding
// id (a CVE). A rule added with --finding has an empty RuleID, so matching only
// on RuleID left it removable by uuid alone — and `ignore list` does not print
// uuids, which made it unremovable in practice.
func (m *Memory) DeactivateSuppression(uuid, anchorID, repoFullName string) int {
	n := 0
	for i, s := range m.Suppressions {
		if !s.IsActive {
			continue
		}
		matchesAnchor := anchorID != "" && (s.RuleID == anchorID || s.FindingID == anchorID)
		switch {
		case uuid != "" && s.UUID == uuid:
		case uuid == "" && matchesAnchor && (repoFullName == "" || s.RepositoryFullName == repoFullName):
		default:
			continue
		}
		m.Suppressions[i].IsActive = false
		n++
	}
	return n
}

// ActiveSuppressions returns the currently-active, unexpired suppression rules.
func (m *Memory) ActiveSuppressions(now int64) []SuppressionRecord {
	out := make([]SuppressionRecord, 0, len(m.Suppressions))
	for _, s := range m.Suppressions {
		if !s.IsActive {
			continue
		}
		if s.ExpiresAt > 0 && s.ExpiresAt <= now {
			continue
		}
		out = append(out, s)
	}
	return out
}

func suppressionSameIdentity(a, b SuppressionRecord) bool {
	if a.UUID != "" && b.UUID != "" {
		return a.UUID == b.UUID
	}
	// nosec (and other snippet-anchored) rules move as code drifts, so identity
	// must NOT depend on file/line. Match on the pinned snippet + rule + repo,
	// which survive a rename or line shift.
	if a.Snippet != "" && b.Snippet != "" && strings.EqualFold(a.Origin, b.Origin) {
		return strings.EqualFold(a.RuleID, b.RuleID) &&
			a.RepositoryFullName == b.RepositoryFullName &&
			strings.TrimSpace(a.Snippet) == strings.TrimSpace(b.Snippet)
	}
	if a.RuleID == "" || b.RuleID == "" {
		return false
	}
	return strings.EqualFold(a.RuleID, b.RuleID) &&
		a.RepositoryFullName == b.RepositoryFullName &&
		a.FilePath == b.FilePath
}
