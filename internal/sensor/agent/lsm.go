package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/lsmguard"
	"github.com/vulnetix/cli/v3/internal/sensor/tetragon"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// lsmEntries picks the exact program paths to refuse in the kernel: Sigma
// rules from verified feeds, not disabled, whose effective mode (after any
// promote or demote) is block.
func lsmEntries(rules []feed.Rule, verdicts *decide.Engine) []lsmguard.Entry {
	var blocking []feed.Rule
	for _, r := range rules {
		rule, ok := verdicts.Rule(decide.RuleRef{Table: r.RuleTable, UUID: r.RuleUUID})
		if ok && rule.Verified && rule.Mode == decide.Block && !r.Disabled {
			blocking = append(blocking, r)
		}
	}
	var out []lsmguard.Entry
	for path, r := range tetragon.ExactImages(blocking) {
		out = append(out, lsmguard.Entry{Path: path, Rule: decide.RuleRef{Table: r.RuleTable, UUID: r.RuleUUID}})
	}

	return out
}

// syncLSM brings the kernel's block map in line with the rules and the mode.
// Monitor reports matches without refusing; guard and enforce refuse, since a
// refused exec can be allowed again.
func (a *Agent) syncLSM() {
	if a.lsm == nil {
		return
	}
	a.mu.Lock()
	rules := a.feedRules
	a.mu.Unlock()
	if err := a.lsm.SetEnforce(a.Verdicts.Mode() != decide.Monitor); err != nil {
		a.cfg.Logf("sensor: bpf lsm mode: %v", err)
	}
	missing, err := a.lsm.Sync(lsmEntries(rules, a.Verdicts), a.cfg.HostRoot)
	if err != nil {
		a.cfg.Logf("sensor: bpf lsm sync: %v", err)
	}
	if len(missing) > 0 {
		a.cfg.Logf("sensor: bpf lsm: %d rule paths are not on this host", len(missing))
	}
}

// runLSM reports each exec the kernel program matched.
func (a *Agent) runLSM(ctx context.Context) {
	a.lsm.Run(ctx, func(r lsmguard.Refusal) {
		action, reason := decide.Blocked, "refused in the kernel by the BPF LSM guard"
		if !r.Enforced {
			action, reason = decide.Allowed, "matched in the kernel; monitor mode reports only"
		}
		a.Enqueue(uplink.Event{
			EventKey:    randomKey(),
			RuleTable:   r.Rule.Table,
			RuleUUID:    r.Rule.UUID,
			Lane:        "countermeasure",
			SubjectKind: "process",
			Subject:     r.Path,
			Action:      string(action),
			Detail:      map[string]any{"pid": r.PID, "reason": reason},
			ObservedAt:  time.Now().UnixMilli(),
		})
	})
}

// randomKey names one refusal; each is its own event.
func randomKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])

	return hex.EncodeToString(b[:])
}
