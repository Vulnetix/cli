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
func (m *Memory) DeactivateSuppression(uuid, ruleID, repoFullName string) int {
	n := 0
	for i, s := range m.Suppressions {
		if !s.IsActive {
			continue
		}
		switch {
		case uuid != "" && s.UUID == uuid:
		case uuid == "" && ruleID != "" && s.RuleID == ruleID && (repoFullName == "" || s.RepositoryFullName == repoFullName):
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
	if a.RuleID == "" || b.RuleID == "" {
		return false
	}
	return strings.EqualFold(a.RuleID, b.RuleID) &&
		a.RepositoryFullName == b.RepositoryFullName &&
		a.FilePath == b.FilePath
}
