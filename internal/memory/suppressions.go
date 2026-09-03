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
		if !s.IsActive || !suppressionMatchesHandle(s, uuid, anchorID, repoFullName) {
			continue
		}
		m.Suppressions[i].IsActive = false
		n++
	}
	return n
}

// MatchingSuppressionUUIDs returns the server uuids of the active rules a
// remove would hit. The backend's deactivate endpoint keys on uuid or ruleId,
// and an inventory rule has no ruleId — so the caller has to resolve uuids
// locally first, or the local rule goes quiet while the org-wide one stays in
// force.
func (m *Memory) MatchingSuppressionUUIDs(uuid, anchorID, repoFullName string) []string {
	var out []string
	for _, s := range m.Suppressions {
		if !s.IsActive || s.UUID == "" || !suppressionMatchesHandle(s, uuid, anchorID, repoFullName) {
			continue
		}
		out = append(out, s.UUID)
	}
	return out
}

// suppressionMatchesHandle reports whether a record is the one a `remove`
// names. anchorID matches any anchor a rule can carry: a rego rule id, a
// finding id (a CVE), or an inventory component value.
func suppressionMatchesHandle(s SuppressionRecord, uuid, anchorID, repoFullName string) bool {
	if uuid != "" {
		return s.UUID == uuid
	}
	if anchorID == "" {
		return false
	}
	matchesAnchor := s.RuleID == anchorID || s.FindingID == anchorID ||
		strings.EqualFold(s.TargetValue, anchorID)
	return matchesAnchor && (repoFullName == "" || s.RepositoryFullName == repoFullName)
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
	// A matching uuid settles it, but a differing one must NOT: `ignore add`
	// pushes to the backend first and stamps whatever uuid the server minted,
	// and the create endpoint mints a fresh one every call. Returning early on
	// a mismatch made every re-add of the same rule append a duplicate rather
	// than replace, which then filtered the same component twice.
	if a.UUID != "" && b.UUID != "" && a.UUID == b.UUID {
		return true
	}
	// nosec (and other snippet-anchored) rules move as code drifts, so identity
	// must NOT depend on file/line. Match on the pinned snippet + rule + repo,
	// which survive a rename or line shift.
	if a.Snippet != "" && b.Snippet != "" && strings.EqualFold(a.Origin, b.Origin) {
		return strings.EqualFold(a.RuleID, b.RuleID) &&
			a.RepositoryFullName == b.RepositoryFullName &&
			strings.TrimSpace(a.Snippet) == strings.TrimSpace(b.Snippet)
	}
	// Inventory rules (crypto/ai) carry no rego rule id, so the RuleID guard
	// below would call every one of them distinct and `ignore add --value` would
	// append a duplicate on every run. Their identity is the value they anchor,
	// scoped the same way the matcher scopes them.
	if a.TargetValue != "" && b.TargetValue != "" {
		return strings.EqualFold(a.Category, b.Category) &&
			strings.EqualFold(a.TargetValue, b.TargetValue) &&
			a.RepositoryFullName == b.RepositoryFullName &&
			a.FilePath == b.FilePath
	}
	if a.RuleID == "" || b.RuleID == "" {
		return false
	}
	return strings.EqualFold(a.RuleID, b.RuleID) &&
		a.RepositoryFullName == b.RepositoryFullName &&
		a.FilePath == b.FilePath
}
