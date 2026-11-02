package cmd

import (
	"errors"
	"strings"
)

// ownerOnlyKinds decide who can act for the tenant: its settings, its people,
// its machine credentials and its secrets. The console lets only an owner
// token carry them (an admin token cannot), so planning, applying or exporting
// one with anything less is refused with a 403.
var ownerOnlyKinds = map[string]bool{"Organization": true, "Member": true, "ServiceAccount": true, "VaultEntry": true}

// ownerKindHint names the owner-only kinds among docs when err is a 403, so a
// refusal says which documents need an owner token.
func ownerKindHint(err error, docs []configDocument) string {
	var he *configHTTPError
	if !errors.As(err, &he) || he.Status != 403 {
		return ""
	}
	seen := map[string]bool{}
	var kinds []string
	for _, d := range docs {
		if ownerOnlyKinds[d.Kind] && !seen[d.Kind] {
			seen[d.Kind] = true
			kinds = append(kinds, d.Kind)
		}
	}
	if len(kinds) == 0 {
		return ""
	}
	return strings.Join(kinds, ", ") + " can only be planned and applied with an owner token"
}
