// Package agent runs the sensor: it loads rules from the feeds, registers with
// what compiled, serves the proxies, ships events and applies decisions.
//
// Losing the platform does not stop the sensor. Rules already compiled keep
// running, decisions already applied keep applying, and events wait in a
// bounded queue until the uplink answers again. If the queue fills, the oldest
// events are dropped and the count is reported with the next batch, so a gap
// is visible rather than silent.
package agent

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/execwatch"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/proxy"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

// Config is how the sensor is run.
type Config struct {
	SensorKey string
	Version   string
	Mode      decide.Mode
	Hold      time.Duration
	Facts     host.Facts

	Feeds  []*feed.Source
	Uplink *uplink.Client

	// Reverse is nil when the sensor does not front a port; Egress is nil
	// when it does not proxy outbound calls.
	Reverse       *proxy.Reverse
	ReverseListen string
	Egress        *proxy.Egress
	EgressListen  string

	// TetragonExport is Tetragon's JSON export file. When set, every process
	// start is checked against the feeds' file-hash indicators.
	TetragonExport string
	// HostRoot is where the host's filesystem is visible to the sensor, for
	// hashing what a process ran: "/" on the host, or a mount in a container.
	HostRoot string

	FeedEvery      time.Duration
	HeartbeatEvery time.Duration
	FlushEvery     time.Duration
	QueueLimit     int

	Logf func(string, ...any)
}

// Agent is a running sensor.
type Agent struct {
	cfg      Config
	Verdicts *decide.Engine
	Rules    *proxy.Rules

	mu      sync.Mutex
	queue   []uplink.Event
	dropped int
	etag    string
	cursor  int64
}

// New builds an agent. The proxies in cfg are wired to its verdict engine and
// rule set.
func New(cfg Config) *Agent {
	if cfg.FeedEvery <= 0 {
		cfg.FeedEvery = 5 * time.Minute
	}
	if cfg.HeartbeatEvery <= 0 {
		cfg.HeartbeatEvery = 5 * time.Minute
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}
	if cfg.QueueLimit <= 0 {
		cfg.QueueLimit = 10000
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	a := &Agent{
		cfg:      cfg,
		Verdicts: decide.New(cfg.Mode, decide.Config{Hold: cfg.Hold}),
		Rules:    &proxy.Rules{},
	}
	if cfg.Reverse != nil {
		cfg.Reverse.Rules, cfg.Reverse.Verdicts, cfg.Reverse.Report = a.Rules, a.Verdicts, a.Enqueue
	}
	if cfg.Egress != nil {
		cfg.Egress.Rules, cfg.Egress.Verdicts, cfg.Egress.Report = a.Rules, a.Verdicts, a.Enqueue
	}

	return a
}

// Enqueue adds an event to the outbound queue.
func (a *Agent) Enqueue(e uplink.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.queue) >= a.cfg.QueueLimit {
		a.queue = a.queue[1:]
		a.dropped++
	}
	a.queue = append(a.queue, e)
}

// Run serves until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	loads := a.RefreshRules(ctx)
	if err := a.register(ctx, loads); err != nil {
		a.cfg.Logf("sensor: register failed, will retry: %v", err)
	}

	var servers []*http.Server
	serve := func(addr string, h http.Handler) {
		if h == nil || addr == "" {
			return
		}
		srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				a.cfg.Logf("sensor: listener %s stopped: %v", addr, err)
			}
		}()
	}
	if a.cfg.Reverse != nil {
		serve(a.cfg.ReverseListen, a.cfg.Reverse)
	}
	if a.cfg.Egress != nil {
		serve(a.cfg.EgressListen, a.cfg.Egress)
	}

	go a.decisionLoop(ctx)

	if a.cfg.TetragonExport != "" {
		w := &execwatch.Watcher{Root: a.cfg.HostRoot, Rules: a.Rules.Load, Verdicts: a.Verdicts, Report: a.Enqueue}
		go func() {
			if err := execwatch.Follow(ctx, a.cfg.TetragonExport, w.Check); err != nil {
				a.cfg.Logf("sensor: stopped reading %s: %v", a.cfg.TetragonExport, err)
			}
		}()
	}

	feedTick := time.NewTicker(a.cfg.FeedEvery)
	beat := time.NewTicker(a.cfg.HeartbeatEvery)
	flush := time.NewTicker(a.cfg.FlushEvery)
	defer feedTick.Stop()
	defer beat.Stop()
	defer flush.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			for _, s := range servers {
				_ = s.Shutdown(shutdown)
			}
			a.Flush(shutdown)
			cancel()

			return nil
		case <-feedTick.C:
			if loads := a.RefreshRules(ctx); loads != nil {
				if err := a.register(ctx, loads); err != nil {
					a.cfg.Logf("sensor: register failed: %v", err)
				}
			}
		case <-beat.C:
			if err := a.register(ctx, nil); err != nil {
				a.cfg.Logf("sensor: heartbeat failed: %v", err)
			}
		case <-flush.C:
			a.Flush(ctx)
		}
	}
}

// RefreshRules fetches every feed and, when any changed, compiles and installs
// the merged rule set. It returns the rule loads to report, or nil when
// nothing changed or nothing could be fetched.
func (a *Agent) RefreshRules(ctx context.Context) []uplink.RuleLoad {
	var (
		rules    []feed.Rule
		verified = map[decide.RuleRef]bool{}
		changed  bool
		etags    string
	)
	for _, src := range a.cfg.Feeds {
		got, err := src.Fetch(ctx)
		switch {
		case errors.Is(err, feed.ErrNotModified):
			continue
		case err != nil:
			a.cfg.Logf("sensor: feed %s: %v", src.BaseURL, err)

			continue
		}
		changed = true
		etags += got.ETag
		if !got.Verified {
			a.cfg.Logf("sensor: feed %s is not verified (%s); its rules report and never block", src.BaseURL, got.Unverified)
		}
		for _, r := range got.Rules {
			rules = append(rules, r)
			verified[decide.RuleRef{Table: r.RuleTable, UUID: r.RuleUUID}] = got.Verified
		}
	}
	if !changed {
		return nil
	}

	set, results := engine.Compile(rules)
	var loaded []decide.Rule
	loads := make([]uplink.RuleLoad, 0, len(results))
	for _, r := range results {
		ref := decide.RuleRef{Table: r.Rule.RuleTable, UUID: r.Rule.RuleUUID}
		mode := decide.Log
		if r.Rule.DeployMode == "block" {
			mode = decide.Block
		}
		if r.Status == engine.Compiled {
			loaded = append(loaded, decide.Rule{Ref: ref, Mode: mode, Verified: verified[ref]})
		}
		loads = append(loads, uplink.RuleLoad{RuleTable: ref.Table, RuleUUID: ref.UUID, Status: r.Status, Reason: r.Reason, Mode: string(mode)})
	}
	a.Verdicts.SetRules(loaded)
	a.Rules.Store(set)
	a.mu.Lock()
	a.etag = etags
	a.mu.Unlock()
	a.cfg.Logf("sensor: %d rules compiled of %d", len(loaded), len(results))

	// The effective mode, after promotions, is what the console shows.
	for i := range loads {
		if r, ok := a.Verdicts.Rule(decide.RuleRef{Table: loads[i].RuleTable, UUID: loads[i].RuleUUID}); ok {
			loads[i].Mode = string(r.Mode)
		}
	}

	return loads
}

func (a *Agent) register(ctx context.Context, loads []uplink.RuleLoad) error {
	if a.cfg.Uplink == nil {
		return nil
	}
	a.mu.Lock()
	etag := a.etag
	a.mu.Unlock()
	_, err := a.cfg.Uplink.Register(ctx, uplink.Registration{
		SensorKey:     a.cfg.SensorKey,
		ComputeKind:   a.cfg.Facts.ComputeKind,
		ResourceArn:   a.cfg.Facts.ResourceArn,
		Hostname:      a.cfg.Facts.Hostname,
		Mode:          string(a.Verdicts.Mode()),
		Version:       a.cfg.Version,
		KernelVersion: a.cfg.Facts.KernelVersion,
		Capabilities:  a.capabilities(),
		RulesetEtag:   etag,
		RuleLoads:     loads,
	})

	return err
}

// capabilities says what this sensor actually does on this host. Only what is
// running is claimed: the console reads it to decide whether to say the
// sensor can block, and a capability the sensor has but does not use would
// make that statement false.
func (a *Agent) capabilities() map[string]bool {
	return map[string]bool{
		"proxy": a.cfg.Reverse != nil || a.cfg.Egress != nil,
		"dns":   false,
		// Kernel events through Tetragon's eBPF, read for detection. Nothing
		// here refuses an exec in the kernel, so bpfLsm stays off.
		"ebpf":   a.cfg.TetragonExport != "",
		"bpfLsm": false,
		"ptrace": false,
	}
}

// Flush posts the queue in batches of 500. A batch that fails goes back to
// the front of the queue.
func (a *Agent) Flush(ctx context.Context) {
	if a.cfg.Uplink == nil {
		return
	}
	for {
		a.mu.Lock()
		if len(a.queue) == 0 {
			a.mu.Unlock()

			return
		}
		n := min(len(a.queue), 500)
		batch := append([]uplink.Event(nil), a.queue[:n]...)
		dropped := a.dropped
		a.queue = a.queue[n:]
		a.dropped = 0
		a.mu.Unlock()

		if dropped > 0 && len(batch) > 0 {
			if batch[0].Detail == nil {
				batch[0].Detail = map[string]any{}
			}
			batch[0].Detail["droppedBefore"] = dropped
		}
		if _, rejected, err := a.cfg.Uplink.PostEvents(ctx, a.cfg.SensorKey, batch); err != nil {
			a.mu.Lock()
			a.queue = append(batch, a.queue...)
			a.dropped += dropped
			a.mu.Unlock()
			a.cfg.Logf("sensor: event post failed, %d kept for retry: %v", len(batch), err)

			return
		} else if len(rejected) > 0 {
			a.cfg.Logf("sensor: server refused %d events: %v", len(rejected), rejected)
		}
	}
}

// decisionLoop long-polls decisions and applies them.
func (a *Agent) decisionLoop(ctx context.Context) {
	if a.cfg.Uplink == nil {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		ds, cursor, err := a.cfg.Uplink.PollDecisions(ctx, a.cfg.SensorKey, a.cursor, 25*time.Second)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)

			continue
		}
		backoff = time.Second
		modeBefore := a.Verdicts.Mode()
		for _, d := range ds {
			a.Verdicts.Apply(ToDecision(d))
		}
		a.cursor = cursor
		if a.Verdicts.Mode() != modeBefore {
			if err := a.register(ctx, nil); err != nil {
				a.cfg.Logf("sensor: mode change not reported: %v", err)
			}
		}
	}
}

// ToDecision converts a platform decision for the verdict engine.
func ToDecision(d uplink.Decision) decide.Decision {
	out := decide.Decision{
		UUID:      d.UUID,
		Rule:      decide.RuleRef{Table: d.RuleTable, UUID: d.RuleUUID},
		Subject:   d.Subject,
		Verdict:   d.Verdict,
		Value:     d.Value,
		Revoked:   d.RevokedAt > 0,
		DecidedAt: time.UnixMilli(d.DecidedAt),
	}
	if d.Until > 0 {
		out.Until = time.UnixMilli(d.Until)
	}
	if out.Subject == "" {
		out.Subject = "*"
	}

	return out
}
