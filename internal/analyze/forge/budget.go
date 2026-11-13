package forge

// The request budget lives in internal/ghquota, which the licence lookups share: both
// spend the same token, and inside GitHub Actions the same repository-wide quota.

import "github.com/vulnetix/cli/v4/internal/ghquota"

type budget = ghquota.Budget

// newBudget keeps half the token's hourly limit for the other users of the token.
func newBudget() *budget { return ghquota.NewBudget() }

// IsRateLimit reports whether an error is GitHub telling us to stop.
func IsRateLimit(err error) bool { return ghquota.IsRateLimit(err) }
