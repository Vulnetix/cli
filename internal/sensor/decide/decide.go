// Package decide is the runtime sensor's verdict engine: given a rule match,
// what does the sensor do about it, right now, on this host.
//
// Three modes:
//
//   - monitor reports every match and blocks nothing.
//   - guard holds a match on a rule safe to block (a request denied, an exec
//     refused, a connection dropped) until a person confirms a block or
//     releases it on the resolve pages, or the hold lapses to allow.
//   - enforce blocks matches on rules safe to block, without asking.
//
// The rules that keep it from causing the outage it exists to prevent:
//
//   - Only a reversible action is ever held. Stopping a process cannot be
//     undone when the hold is released, so a hold never stops one.
//   - A rule not from a verified feed, or one whose own start mode is log,
//     is reported and never blocked, in any mode.
//   - A health check is never held: a held probe takes the workload out of
//     its load balancer, which is the outage.
//   - A rule that holds too many distinct subjects in a short window trips a
//     breaker and reverts to reporting until a person decides about it. A
//     misfiring rule in guard mode would otherwise hold every request.
//   - A hold that lapses unanswered allows that subject from then on, rather
//     than holding it again, which would turn guard into enforce by neglect.
//
// The engine is pure: time is passed in, nothing is read from the host.
package decide

import (
	"sort"
	"sync"
	"time"
)

// Mode is the sensor's mode.
type Mode string

const (
	Monitor Mode = "monitor"
	Guard   Mode = "guard"
	Enforce Mode = "enforce"
)

// ValidMode reports whether m is one of the three modes.
func ValidMode(m string) bool {
	return m == string(Monitor) || m == string(Guard) || m == string(Enforce)
}

// RuleMode is the mode a rule runs in: block, or log only.
type RuleMode string

const (
	Block RuleMode = "block"
	Log   RuleMode = "log"
)

// Action is what the sensor did.
type Action string

const (
	Allowed Action = "allowed"
	Held    Action = "held"
	Blocked Action = "blocked"
)

// RuleRef names a rule the way the platform does.
type RuleRef struct {
	Table string
	UUID  string
}

// Rule is one loaded rule.
type Rule struct {
	Ref  RuleRef
	Mode RuleMode
	// FeedMode is the start mode the feed gave the rule, which a revoked
	// promote or demote returns it to.
	FeedMode RuleMode
	// Verified is true when the rule came from a feed whose signature and
	// file hashes checked out. An unverified rule never blocks.
	Verified bool
}

// Match is one rule firing on one subject.
type Match struct {
	Rule    RuleRef
	Subject string
	// Reversible is true when the response to this match can be undone: a
	// denied request, a refused exec, a dropped new connection, a quarantined
	// file. Stopping a running process is not.
	Reversible bool
	// HealthCheck marks a request on a path the operator named as a health
	// check. It is never held.
	HealthCheck bool
}

// Verdict is the engine's answer.
type Verdict struct {
	Action    Action
	HoldUntil time.Time
	// Reason is one short phrase saying why, reported with the event.
	Reason string
}

// Decision is a person's decision, as the platform sends it.
type Decision struct {
	UUID      string
	Rule      RuleRef
	Subject   string // "*" for the whole rule
	Verdict   string // block | allow | promote | demote | mode
	Value     string // the mode, for verdict "mode"
	Until     time.Time
	Revoked   bool
	DecidedAt time.Time
}

// Config tunes the engine.
type Config struct {
	// Hold is how long a guard-mode hold waits for a person.
	Hold time.Duration
	// BreakerSubjects distinct subjects held by one rule inside
	// BreakerWindow trips that rule's breaker.
	BreakerSubjects int
	BreakerWindow   time.Duration
}

// DefaultConfig is fifteen minutes to decide, and a breaker at twenty distinct
// subjects in five minutes.
func DefaultConfig() Config {
	return Config{Hold: 15 * time.Minute, BreakerSubjects: 20, BreakerWindow: 5 * time.Minute}
}

type subjectKey struct {
	Rule    RuleRef
	Subject string
}

type holdState struct {
	Until  time.Time
	Lapsed bool
}

// Engine holds the sensor's state. Safe for concurrent use.
type Engine struct {
	mu  sync.Mutex
	cfg Config

	mode  Mode
	rules map[RuleRef]Rule

	// From decisions, keyed by decision uuid so a revocation finds them.
	decisions map[string]Decision

	holds map[subjectKey]holdState
	// recent holds per rule, for the breaker
	recent  map[RuleRef][]time.Time
	tripped map[RuleRef]time.Time
}

// New returns an engine in the given mode with no rules loaded.
func New(mode Mode, cfg Config) *Engine {
	if cfg.Hold <= 0 {
		cfg.Hold = DefaultConfig().Hold
	}
	if cfg.BreakerSubjects <= 0 {
		cfg.BreakerSubjects = DefaultConfig().BreakerSubjects
	}
	if cfg.BreakerWindow <= 0 {
		cfg.BreakerWindow = DefaultConfig().BreakerWindow
	}
	if !ValidMode(string(mode)) {
		mode = Monitor
	}

	return &Engine{
		cfg: cfg, mode: mode,
		rules:     map[RuleRef]Rule{},
		decisions: map[string]Decision{},
		holds:     map[subjectKey]holdState{},
		recent:    map[RuleRef][]time.Time{},
		tripped:   map[RuleRef]time.Time{},
	}
}

// Mode returns the current mode.
func (e *Engine) Mode() Mode {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.mode
}

// SetRules replaces the loaded rule set. Holds and decisions about rules that
// are gone are kept: a rule dropped and re-added keeps its history.
func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	next := make(map[RuleRef]Rule, len(rules))
	for _, r := range rules {
		if r.Mode != Block {
			r.Mode = Log
		}
		r.FeedMode = r.Mode
		next[r.Ref] = r
	}
	// A promote or demote decision outranks the feed's start mode.
	for _, d := range e.decisions {
		if r, ok := next[d.Rule]; ok {
			switch d.Verdict {
			case "promote":
				r.Mode = Block
			case "demote":
				r.Mode = Log
			}
			next[d.Rule] = r
		}
	}
	e.rules = next
}

// Rule returns a loaded rule's effective state.
func (e *Engine) Rule(ref RuleRef) (Rule, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[ref]

	return r, ok
}

// Decide answers one match.
func (e *Engine) Decide(m Match, now time.Time) Verdict {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, ok := e.rules[m.Rule]
	if !ok {
		return Verdict{Action: Allowed, Reason: "rule not loaded"}
	}
	key := subjectKey{Rule: m.Rule, Subject: m.Subject}

	// A person's decisions first: they are about this rule and subject on
	// purpose, and outrank the rule's own start mode.
	if d, ok := e.applicable(m.Rule, m.Subject, "allow", now); ok {
		if d.Subject == "*" {
			return Verdict{Action: Allowed, Reason: "marked a false positive"}
		}

		return Verdict{Action: Allowed, Reason: "allowed by a person"}
	}
	_, confirmed := e.applicable(m.Rule, m.Subject, "block", now)

	if e.mode == Monitor {
		return Verdict{Action: Allowed, Reason: "monitor mode"}
	}
	if !rule.Verified {
		return Verdict{Action: Allowed, Reason: "feed not verified: detect only"}
	}
	if confirmed {
		return Verdict{Action: Blocked, Reason: "block confirmed by a person"}
	}
	if rule.Mode != Block {
		return Verdict{Action: Allowed, Reason: "rule runs in log mode"}
	}
	if m.HealthCheck {
		return Verdict{Action: Allowed, Reason: "health check: never held"}
	}
	if _, tripped := e.tripped[m.Rule]; tripped {
		return Verdict{Action: Allowed, Reason: "circuit breaker open: reporting only"}
	}

	// Enforce stops what it matches, a running process included; that is what
	// enforce was chosen for.
	if e.mode == Enforce {
		return Verdict{Action: Blocked, Reason: "enforce mode"}
	}

	// Guard.
	if !m.Reversible {
		return Verdict{Action: Allowed, Reason: "guard never holds an action it cannot undo"}
	}
	if h, ok := e.holds[key]; ok {
		if h.Lapsed {
			return Verdict{Action: Allowed, Reason: "hold lapsed unanswered"}
		}
		if now.Before(h.Until) {
			return Verdict{Action: Held, HoldUntil: h.Until, Reason: "held for a decision"}
		}
		e.holds[key] = holdState{Until: h.Until, Lapsed: true}

		return Verdict{Action: Allowed, Reason: "hold lapsed unanswered"}
	}

	if e.recordHold(m.Rule, now) {
		e.tripped[m.Rule] = now

		return Verdict{Action: Allowed, Reason: "circuit breaker tripped: too many holds"}
	}
	until := now.Add(e.cfg.Hold)
	e.holds[key] = holdState{Until: until}

	return Verdict{Action: Held, HoldUntil: until, Reason: "held for a decision"}
}

// recordHold counts a new hold against the rule's breaker and reports whether
// it trips.
func (e *Engine) recordHold(ref RuleRef, now time.Time) bool {
	cutoff := now.Add(-e.cfg.BreakerWindow)
	kept := e.recent[ref][:0]
	for _, t := range e.recent[ref] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.recent[ref] = kept

	return len(kept) > e.cfg.BreakerSubjects
}

// applicable finds a live decision of the given verdict for a rule and
// subject, preferring the exact subject over the whole rule.
func (e *Engine) applicable(ref RuleRef, subject, verdict string, now time.Time) (Decision, bool) {
	var whole *Decision
	for _, d := range e.decisions {
		if d.Revoked || d.Verdict != verdict || d.Rule != ref {
			continue
		}
		if !d.Until.IsZero() && !now.Before(d.Until) {
			continue
		}
		if d.Subject == subject {
			return d, true
		}
		if d.Subject == "*" {
			dd := d
			whole = &dd
		}
	}
	if whole != nil {
		return *whole, true
	}

	return Decision{}, false
}

// Apply takes a person's decision into account.
func (e *Engine) Apply(d Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if d.Revoked {
		prev, ok := e.decisions[d.UUID]
		delete(e.decisions, d.UUID)
		if ok {
			e.undo(prev)
		}

		return
	}

	switch d.Verdict {
	case "mode":
		if ValidMode(d.Value) {
			e.mode = Mode(d.Value)
		}

		return
	case "promote", "demote":
		if r, ok := e.rules[d.Rule]; ok {
			r.Mode = Log
			if d.Verdict == "promote" {
				r.Mode = Block
			}
			e.rules[d.Rule] = r
		}
		// A person decided about this rule: its breaker closes.
		delete(e.tripped, d.Rule)
		delete(e.recent, d.Rule)
	case "block", "allow":
		// Whatever was held is decided now.
		if d.Subject == "*" {
			for k := range e.holds {
				if k.Rule == d.Rule {
					delete(e.holds, k)
				}
			}
			delete(e.tripped, d.Rule)
			delete(e.recent, d.Rule)
		} else {
			delete(e.holds, subjectKey{Rule: d.Rule, Subject: d.Subject})
		}
	default:
		return
	}
	if d.UUID != "" {
		e.decisions[d.UUID] = d
	}
}

// undo reverses a revoked promote or demote; block and allow need nothing,
// because they are only ever read from e.decisions.
func (e *Engine) undo(d Decision) {
	if d.Verdict != "promote" && d.Verdict != "demote" {
		return
	}
	if r, ok := e.rules[d.Rule]; ok {
		r.Mode = r.FeedMode
		e.rules[d.Rule] = r
	}
}

// Pending lists live holds, soonest to lapse first.
type PendingHold struct {
	Rule    RuleRef
	Subject string
	Until   time.Time
}

func (e *Engine) Pending(now time.Time) []PendingHold {
	e.mu.Lock()
	defer e.mu.Unlock()

	var out []PendingHold
	for k, h := range e.holds {
		if !h.Lapsed && now.Before(h.Until) {
			out = append(out, PendingHold{Rule: k.Rule, Subject: k.Subject, Until: h.Until})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })

	return out
}

// Tripped lists rules whose breaker is open.
func (e *Engine) Tripped() []RuleRef {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]RuleRef, 0, len(e.tripped))
	for r := range e.tripped {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })

	return out
}
