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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v4/internal/binpkg"
	"github.com/vulnetix/cli/v4/internal/sensor/addongate"
	"github.com/vulnetix/cli/v4/internal/sensor/decide"
	"github.com/vulnetix/cli/v4/internal/sensor/dnsguard"
	"github.com/vulnetix/cli/v4/internal/sensor/engine"
	"github.com/vulnetix/cli/v4/internal/sensor/execwatch"
	"github.com/vulnetix/cli/v4/internal/sensor/feed"
	"github.com/vulnetix/cli/v4/internal/sensor/host"
	"github.com/vulnetix/cli/v4/internal/sensor/hostcheck"
	"github.com/vulnetix/cli/v4/internal/sensor/inventory"
	"github.com/vulnetix/cli/v4/internal/sensor/lsmguard"
	"github.com/vulnetix/cli/v4/internal/sensor/proxy"
	"github.com/vulnetix/cli/v4/internal/sensor/sdnotify"
	"github.com/vulnetix/cli/v4/internal/sensor/siem"
	"github.com/vulnetix/cli/v4/internal/sensor/uplink"
	"github.com/vulnetix/cli/v4/internal/sysinv"
)

// Config is how the sensor is run.
type Config struct {
	SensorKey string
	Version   string
	Mode      decide.Mode
	Hold      time.Duration
	Facts     host.Facts

	Feeds  []feed.Fetcher
	Uplink *uplink.Client

	// Reverse is nil when the sensor does not front a port; Egress is nil
	// when it does not proxy outbound calls.
	Reverse       *proxy.Reverse
	ReverseListen string
	Egress        *proxy.Egress
	EgressListen  string

	// DNSListen is the UDP address the DNS guard answers on, forwarding to
	// DNSUpstream. Empty leaves DNS alone.
	DNSListen   string
	DNSUpstream string

	// OnHealthy is called once, after the first report the server accepts. The
	// self-update treats a new release as sound only after this.
	OnHealthy func()

	// TetragonExport is Tetragon's JSON export file. When set, every process
	// start is checked against the feeds' file-hash indicators.
	TetragonExport string
	// HostRoot is where the host's filesystem is visible to the sensor, for
	// hashing what a process ran: "/" on the host, or a mount in a container.
	HostRoot string

	// BPFLSM loads the BPF LSM exec guard (internal/sensor/lsmguard), which
	// refuses execs of the exact paths block-mode rules name, in the kernel.
	// Needs the bpf LSM and root; off by default.
	BPFLSM bool

	// ExecGuard is a workload command the sensor starts under its seccomp exec
	// guard (vulnetix-sensor run -- <command>), for compute with no eBPF such
	// as Fargate. Every exec the workload makes waits for the rules; Run
	// returns when the workload exits, with its code in ExitCode.
	ExecGuard []string

	// InventoryEvery is how often the in-use package inventory is read from
	// HostRoot/proc and reported. Zero turns it off.
	InventoryEvery time.Duration

	// SIEM, when set, gets a copy of every DNS and egress decision, matched
	// or not, for Guardian (--forward siem). Nil forwards nothing.
	SIEM *siem.Forwarder

	// PollConfig, when set, is called every ConfigEvery (default five
	// minutes) for an enrolled sensor's profile changes. It applies what it
	// can to the running agent; returning true stops Run cleanly so the
	// service manager restarts the sensor with the new configuration.
	PollConfig  func(ctx context.Context, a *Agent) (restart bool)
	ConfigEvery time.Duration
	// ConfigEtag is the etag of the profile config the sensor started on. When
	// the decisions long-poll names another one, PollConfig runs at once (at
	// most every ConfigSoonest, default ten seconds) rather than waiting for
	// the tick, which stays as the fallback. PollConfig reports the etag it
	// applies with SetConfigEtag.
	ConfigEtag    string
	ConfigSoonest time.Duration

	// Notify is sd_notify, sdnotify.Notify outside tests. READY=1 is sent
	// when Run starts and WATCHDOG=1 at half the unit's watchdog interval.
	Notify           func(state string) (bool, error)
	WatchdogInterval time.Duration

	FeedEvery      time.Duration
	HeartbeatEvery time.Duration
	FlushEvery     time.Duration
	QueueLimit     int

	Logf func(string, ...any)
}

// Agent is a running sensor.
type Agent struct {
	healthy  sync.Once
	cfg      Config
	Verdicts *decide.Engine
	Rules    *proxy.Rules
	// ExitCode is the guarded workload's exit code, once Run returns.
	ExitCode int
	// Restart is set when Run returned because PollConfig asked for a
	// restart.
	Restart bool

	lsm       *lsmguard.Guard
	feedRules []feed.Rule // the merged feed rules, for the BPF LSM's paths
	// lastGood is each feed's last good fetch, by Ref: every compile is the
	// union of them, so one feed changing never drops another's rules, and a
	// feed that fails keeps the rules it had. feedsChanged forces a compile
	// after SetFeeds, so a feed taken out of the list is dropped.
	lastGood     map[string]feed.Loaded
	feedsChanged bool

	// configEtag is the profile config the sensor runs (under mu); configNow
	// asks Run for a config poll now.
	configEtag string
	configNow  chan struct{}

	mu      sync.Mutex
	queue   []uplink.Event
	dropped int
	etag    string
	cursor  int64

	started time.Time
	passes  passes

	// flushFails and flushAfter back event posts off after a failure, so a
	// refused or unreachable site costs a request (and a log line) every few
	// minutes rather than every FlushEvery.
	flushFails int
	flushAfter time.Time

	// addonNoted is set once the operator has been told, in the log, that the
	// platform wants an add-on; it clears on the next answer that is not a
	// denial, so a lapse that recurs is announced again.
	addonNoted bool
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
	if cfg.ConfigEvery <= 0 {
		cfg.ConfigEvery = 5 * time.Minute
	}
	if cfg.ConfigSoonest <= 0 {
		cfg.ConfigSoonest = 10 * time.Second
	}
	if cfg.Notify == nil {
		cfg.Notify = sdnotify.Notify
	}
	if cfg.WatchdogInterval <= 0 {
		cfg.WatchdogInterval = sdnotify.WatchdogInterval()
	}
	a := &Agent{
		cfg:        cfg,
		Verdicts:   decide.New(cfg.Mode, decide.Config{Hold: cfg.Hold}),
		Rules:      &proxy.Rules{},
		started:    time.Now(),
		configEtag: cfg.ConfigEtag,
		configNow:  make(chan struct{}, 1),
	}
	if cfg.Reverse != nil {
		cfg.Reverse.Rules, cfg.Reverse.Verdicts, cfg.Reverse.Report = a.Rules, a.Verdicts, a.Enqueue
	}
	if cfg.Egress != nil {
		cfg.Egress.Rules, cfg.Egress.Verdicts, cfg.Egress.Report = a.Rules, a.Verdicts, a.Enqueue
		if cfg.SIEM != nil {
			cfg.Egress.Observe = cfg.SIEM.Egress
		}
	}

	return a
}

// reporting is whether the sensor reports to the platform: it has an uplink
// and the uplink was not stopped by a revoked credential.
func (a *Agent) reporting() bool {
	return a.cfg.Uplink != nil && !a.cfg.Uplink.Stopped()
}

// Mode is the verdict engine's current mode.
func (a *Agent) Mode() decide.Mode { return a.Verdicts.Mode() }

// SetMode changes the mode live, as a profile change does.
func (a *Agent) SetMode(m decide.Mode) {
	a.Verdicts.SetMode(m)
	a.syncLSM()
}

// SetHold changes how long guard mode holds a new match.
func (a *Agent) SetHold(d time.Duration) { a.Verdicts.SetHold(d) }

// SetFeeds replaces the feeds. The next refresh fetches every one of them
// afresh and rebuilds the rule set from the new list only; a feed still in
// the list keeps its last good rules until its new source fetches.
func (a *Agent) SetFeeds(feeds []feed.Fetcher) {
	a.mu.Lock()
	a.cfg.Feeds = feeds
	a.feedsChanged = true
	a.mu.Unlock()
}

// SetConfigEtag records the etag of the profile config the sensor now runs.
func (a *Agent) SetConfigEtag(etag string) {
	a.mu.Lock()
	a.configEtag = etag
	a.mu.Unlock()
}

// noticeConfigEtag asks for a config poll when the site names a profile
// config other than the one the sensor runs.
func (a *Agent) noticeConfigEtag(etag string) {
	if etag == "" || a.cfg.PollConfig == nil {
		return
	}
	a.mu.Lock()
	current := a.configEtag
	a.mu.Unlock()
	bare := func(s string) string { return strings.Trim(strings.TrimPrefix(s, "W/"), `"`) }
	if bare(etag) == bare(current) {
		return
	}
	select {
	case a.configNow <- struct{}{}:
	default:
	}
}

// StopReporting stops the uplink: the sensor keeps enforcing what it has and
// reports nothing more.
func (a *Agent) StopReporting() {
	if a.cfg.Uplink != nil {
		a.cfg.Uplink.Stop()
	}
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
	// Ready as soon as the sensor is up: the first feed fetch can take a
	// minute on a slow network, and a notify unit that is not ready by its
	// start timeout is killed.
	if ok, err := a.cfg.Notify("READY=1"); err != nil {
		a.cfg.Logf("sensor: sd_notify READY failed: %v", err)
	} else if ok && a.cfg.WatchdogInterval > 0 {
		// The ping runs on its own: a feed refresh in the loop below can
		// legitimately outlast the watchdog. What it proves is that the
		// process is alive and scheduled, not stopped or wedged.
		wctx, stopWatchdog := context.WithCancel(ctx)
		defer stopWatchdog()
		go a.watchdog(wctx, a.cfg.WatchdogInterval/2)
	}
	if a.cfg.BPFLSM {
		g, err := lsmguard.Load()
		if err != nil {
			a.cfg.Logf("sensor: bpf lsm guard not loaded, process starts are not refused in the kernel: %v", err)
		} else {
			a.lsm = g
			defer g.Close()
			go a.runLSM(ctx)
		}
	}
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

	// The forwarder outlives ctx by its last flush, so shutdown stops it
	// after the listeners and waits for that flush.
	siemDone := make(chan struct{})
	siemCtx, stopSIEM := context.WithCancel(context.Background())
	defer stopSIEM()
	if a.cfg.SIEM != nil {
		go func() {
			defer close(siemDone)
			a.cfg.SIEM.Run(siemCtx)
		}()
	} else {
		close(siemDone)
	}

	if a.cfg.InventoryEvery > 0 && a.cfg.Uplink != nil {
		go a.inventoryLoop(ctx)
	}

	if a.cfg.DNSListen != "" {
		pc, err := net.ListenPacket("udp", a.cfg.DNSListen)
		if err != nil {
			a.cfg.Logf("sensor: dns guard not started on %s: %v", a.cfg.DNSListen, err)
		} else {
			g := &dnsguard.Guard{Upstream: a.cfg.DNSUpstream, Rules: a.Rules.Load, Verdicts: a.Verdicts, Report: a.Enqueue}
			if a.cfg.SIEM != nil {
				g.Observe = a.cfg.SIEM.DNS
			}
			go func() {
				if err := g.Serve(ctx, pc); err != nil {
					a.cfg.Logf("sensor: dns guard stopped: %v", err)
				}
			}()
		}
	}

	if a.cfg.TetragonExport != "" {
		w := &execwatch.Watcher{Root: a.cfg.HostRoot, Rules: a.Rules.Load, Verdicts: a.Verdicts, Report: a.Enqueue}
		go func() {
			if err := execwatch.Follow(ctx, a.cfg.TetragonExport, w.Check); err != nil {
				a.cfg.Logf("sensor: stopped reading %s: %v", a.cfg.TetragonExport, err)
			}
		}()
	}

	// The guarded workload decides when the sensor stops: a signal goes to
	// the workload (execguard forwards it), and the sensor flushes after it
	// exits.
	var guardDone chan int
	stopped := ctx.Done()
	if len(a.cfg.ExecGuard) > 0 {
		guardDone = make(chan int, 1)
		go a.runExecGuard(guardDone)
		stopped = nil
	}
	shutdown := func() error {
		_, _ = a.cfg.Notify("STOPPING=1")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, s := range servers {
			_ = s.Shutdown(sctx)
		}
		a.Flush(sctx)
		stopSIEM()
		<-siemDone

		return nil
	}

	var configTick <-chan time.Time
	if a.cfg.PollConfig != nil {
		t := time.NewTicker(a.cfg.ConfigEvery)
		defer t.Stop()
		configTick = t.C
	}
	feedTick := time.NewTicker(a.cfg.FeedEvery)
	beat := time.NewTicker(a.cfg.HeartbeatEvery)
	flush := time.NewTicker(a.cfg.FlushEvery)
	defer feedTick.Stop()
	defer beat.Stop()
	defer flush.Stop()

	// pollConfig runs PollConfig and applies what came back; true means Run
	// must stop for a restart.
	var lastConfigPoll time.Time
	pollConfig := func() bool {
		modeBefore := a.Verdicts.Mode()
		lastConfigPoll = time.Now()
		restart := a.cfg.PollConfig(ctx, a)
		a.passes.record("config", lastConfigPoll, nil)
		if restart {
			return true
		}
		// A changed feed list is fetched now rather than at the next
		// feed tick, and a mode change is reported at once.
		loads := a.RefreshRules(ctx)
		if loads != nil || a.Verdicts.Mode() != modeBefore {
			if err := a.register(ctx, loads); err != nil {
				a.cfg.Logf("sensor: register failed: %v", err)
			}
		}

		return false
	}
	// configSoon fires a config poll the long-poll asked for inside the
	// rate limit, once the limit allows it.
	var configSoon <-chan time.Time

	for {
		select {
		case <-stopped:
			return shutdown()
		case code := <-guardDone:
			a.ExitCode = code

			return shutdown()
		case <-feedTick.C:
			if loads := a.RefreshRules(ctx); loads != nil {
				if err := a.register(ctx, loads); err != nil {
					a.cfg.Logf("sensor: register failed: %v", err)
				}
			}
		case <-configTick:
			if pollConfig() {
				a.Restart = true

				return shutdown()
			}
		case <-a.configNow:
			if configSoon != nil {
				continue
			}
			if wait := a.cfg.ConfigSoonest - time.Since(lastConfigPoll); wait > 0 {
				configSoon = time.After(wait)

				continue
			}
			if pollConfig() {
				a.Restart = true

				return shutdown()
			}
		case <-configSoon:
			configSoon = nil
			if pollConfig() {
				a.Restart = true

				return shutdown()
			}
		case <-beat.C:
			if err := a.register(ctx, nil); err != nil {
				a.cfg.Logf("sensor: heartbeat failed: %v", err)
			}
		case <-flush.C:
			if a.flushDue(time.Now()) {
				a.Flush(ctx)
			}
		}
	}
}

// RefreshRules fetches every feed and, when any changed, compiles and installs
// the union of every feed's last good rules: a feed that did not change, or
// failed this round, contributes what it fetched before. It returns the rule
// loads to report, or nil when nothing changed or nothing could be fetched.
func (a *Agent) RefreshRules(ctx context.Context) []uplink.RuleLoad {
	start := time.Now()
	var fetchErr error
	defer func() { a.passes.record("feeds", start, fetchErr) }()
	a.mu.Lock()
	feeds := a.cfg.Feeds
	changed := a.feedsChanged
	a.feedsChanged = false
	a.mu.Unlock()

	fetched := map[string]feed.Loaded{}
	for _, src := range feeds {
		got, err := src.Fetch(ctx)
		switch {
		case errors.Is(err, feed.ErrNotModified):
			continue
		case errors.Is(err, feed.ErrRevoked):
			fetchErr = err
			if a.reporting() {
				a.cfg.Logf("sensor: DEVICE REVOKED: the site refused this sensor's credential fetching feed %s. The sensor keeps enforcing the rules it has and reports nothing more. Re-enroll with: sudo vulnetix-sensor enroll", src.Ref())
				a.StopReporting()
			}

			continue
		case err != nil:
			fetchErr = err
			a.cfg.Logf("sensor: feed %s: %v; keeping its last good rules", src.Ref(), err)

			continue
		}
		changed = true
		fetched[src.Ref()] = got
		if !got.Verified && got.FeedType != feed.RuleTypeIOCList {
			a.cfg.Logf("sensor: feed %s is not verified (%s); its rules report and never block", src.Ref(), got.Unverified)
		}
	}
	if !changed {
		return nil
	}

	// The union, in feed order, of each feed's newest good result. A feed no
	// longer in the list is forgotten.
	var (
		rules    []feed.Rule
		verified = map[decide.RuleRef]bool{}
		etags    string
	)
	a.mu.Lock()
	good := make(map[string]feed.Loaded, len(feeds))
	for _, src := range feeds {
		ref := src.Ref()
		if _, dup := good[ref]; dup {
			continue
		}
		got, ok := fetched[ref]
		if !ok {
			if got, ok = a.lastGood[ref]; !ok {
				continue
			}
		}
		good[ref] = got
		etags += got.ETag
		for _, r := range got.Rules {
			rules = append(rules, r)
			verified[decide.RuleRef{Table: r.RuleTable, UUID: r.RuleUUID}] = got.Verified
		}
	}
	a.lastGood = good
	a.mu.Unlock()

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
	a.feedRules = rules
	a.mu.Unlock()
	a.syncLSM()
	a.cfg.Logf("sensor: %d rules compiled of %d", len(loaded), len(results))

	// The effective mode, after promotions, is what the console shows.
	for i := range loads {
		if r, ok := a.Verdicts.Rule(decide.RuleRef{Table: loads[i].RuleTable, UUID: loads[i].RuleUUID}); ok {
			loads[i].Mode = string(r.Mode)
		}
	}

	return loads
}

// watchdog pings systemd's watchdog every interval until ctx ends.
func (a *Agent) watchdog(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.cfg.Notify("WATCHDOG=1"); err != nil {
				a.cfg.Logf("sensor: sd_notify WATCHDOG failed: %v", err)
			}
		}
	}
}

func (a *Agent) register(ctx context.Context, loads []uplink.RuleLoad) error {
	if !a.reporting() {
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
		Metrics:       a.metrics(time.Now()),
	})
	if err == nil && a.cfg.OnHealthy != nil {
		a.healthy.Do(a.cfg.OnHealthy)
	}

	return err
}

// capabilities says what this sensor actually does on this host. Only what is
// running is claimed: the console reads it to decide whether to say the
// sensor can block, and a capability the sensor has but does not use would
// make that statement false.
func (a *Agent) capabilities() map[string]bool {
	return map[string]bool{
		"proxy": a.cfg.Reverse != nil || a.cfg.Egress != nil,
		"dns":   a.cfg.DNSListen != "",
		// Kernel events through Tetragon's eBPF, read for detection. bpfLsm
		// is on only when the BPF LSM guard loaded and can refuse execs.
		"ebpf":   a.cfg.TetragonExport != "",
		"bpfLsm": a.lsm != nil,
		"ptrace": false,
		// The seccomp exec guard refuses an exec before it runs, for the
		// workload it started and its children only.
		"seccomp": len(a.cfg.ExecGuard) > 0,
	}
}

// Flush posts the queue in batches of 500. A batch that fails goes back to
// the front of the queue.
func (a *Agent) Flush(ctx context.Context) {
	if !a.reporting() {
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
		postStart := time.Now()
		_, rejected, err := a.cfg.Uplink.PostEvents(ctx, a.cfg.SensorKey, batch)
		a.passes.record("events", postStart, err)
		if err != nil {
			a.mu.Lock()
			a.queue = append(batch, a.queue...)
			a.dropped += dropped
			a.flushFails++
			a.flushAfter = time.Now().Add(flushBackoff(a.flushFails))
			a.mu.Unlock()
			if !a.noteAddonDenial(err, "events", fmt.Sprintf("%d events are kept and posts back off", len(batch))) {
				a.cfg.Logf("sensor: event post failed, %d kept for retry: %v", len(batch), err)
			}

			return
		} else if len(rejected) > 0 {
			a.cfg.Logf("sensor: server refused %d events: %v", len(rejected), rejected)
		}
		a.mu.Lock()
		a.flushFails, a.flushAfter = 0, time.Time{}
		a.mu.Unlock()
		a.clearAddonDenial()
	}
}

// decisionLoop long-polls decisions and applies them.
func (a *Agent) decisionLoop(ctx context.Context) {
	if a.cfg.Uplink == nil {
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		if a.cfg.Uplink.Stopped() {
			<-ctx.Done()

			return
		}
		page, err := a.cfg.Uplink.PollDecisionPage(ctx, a.cfg.SensorKey, a.cursor, 25*time.Second)
		ds, cursor := page.Decisions, page.Cursor
		if err != nil {
			a.noteAddonDenial(err, "decisions", "decisions are not applied and the sensor keeps the rules it has")
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)

			continue
		}
		backoff = time.Second
		a.clearAddonDenial()
		modeBefore := a.Verdicts.Mode()
		for _, d := range ds {
			a.Verdicts.Apply(ToDecision(d))
		}
		if len(ds) > 0 {
			// A promote, demote or mode change moves what the kernel refuses.
			a.syncLSM()
		}
		a.cursor = cursor
		a.noticeConfigEtag(page.ConfigEtag)
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

// inventoryLoop reports the in-use packages now and then every
// InventoryEvery. The ownership index is rebuilt each time, because packages
// are installed and upgraded under a running sensor.
func (a *Agent) inventoryLoop(ctx context.Context) {
	tick := time.NewTicker(a.cfg.InventoryEvery)
	defer tick.Stop()
	for {
		invStart := time.Now()
		err := a.ReportInventory(ctx)
		a.passes.record("inventory", invStart, err)
		if err != nil {
			a.cfg.Logf("sensor: inventory not reported: %v", err)
		}
		hcStart := time.Now()
		a.ReportHostChecks(hcStart)
		a.passes.record("hostchecks", hcStart, nil)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ReportInventory reads which installed packages processes map and posts it.
func (a *Agent) ReportInventory(ctx context.Context) error {
	if !a.reporting() {
		return nil
	}
	root := a.cfg.HostRoot
	if root == "" {
		root = "/"
	}
	// The time the host was read orders this report against others.
	readAt := time.Now().UnixMilli()
	res := inventory.Scan(root, binpkg.BuildOwnerIndexFor(root, inventory.MappedPaths(root)))
	// The package databases are read in full each pass; hand what that
	// allocated back to the OS now rather than holding it for six hours.
	defer debug.FreeOSMemory()
	if res.Processes == 0 {
		return fmt.Errorf("no processes readable under %s/proc", strings.TrimRight(root, "/"))
	}
	pkgs := make([]uplink.InventoryPackage, 0, len(res.Packages))
	for _, p := range res.Packages {
		examples := make([]string, 0, len(p.Processes))
		for _, proc := range p.Processes {
			if proc.Exe != "" {
				examples = append(examples, proc.Exe)
			}
		}
		pkgs = append(pkgs, uplink.InventoryPackage{
			Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, State: p.State,
			Processes: max(p.ProcessCount, len(p.Processes)), Examples: examples,
		})
	}
	sys := sysinv.Collect(root)
	pkgs = withInstalled(pkgs, sys)
	report := inventoryReport(pkgs, sys, res.Unreadable)
	report.Seq = readAt
	if report.Complete != nil && !*report.Complete {
		a.cfg.Logf("sensor: inventory is incomplete, the site keeps the last full list: %s", strings.Join(report.Warnings, "; "))
	}
	_, err := a.cfg.Uplink.PostInventoryReport(ctx, a.cfg.SensorKey, report)

	return err
}

// inventoryReport says how much of the host pkgs describes. The site replaces
// its list only with a report it can trust to be the whole host, so a package
// database that exists but could not be read makes the report incomplete, and
// a host whose packages this sensor cannot read at all says so instead of
// posting an empty host. A report with no packages and no reason is left
// unqualified: the site's own guard decides. Processes whose maps could not be
// read only change which packages count as loaded, never the package list, so
// they are a warning and not a reason to distrust it.
func inventoryReport(pkgs []uplink.InventoryPackage, sys sysinv.Result, unreadableProcs int) uplink.InventoryReport {
	r := uplink.InventoryReport{Packages: pkgs, Warnings: append([]string(nil), sys.Warnings...)}
	switch {
	case sys.Unsupported != "":
		r.Unsupported = sys.Unsupported
	case len(sys.Warnings) > 0:
		r.Complete = new(bool)
	case len(sys.Packages) > 0:
		complete := true
		r.Complete = &complete
	}
	if unreadableProcs > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d processes could not be read, so their packages may show as installed rather than loaded", unreadableProcs))
	}

	return r
}

// ReportHostChecks reads the host's configuration and queues each failing
// check as an event in the cis lane. The event key includes the day, so a
// failure that persists is reported once a day, and one that is fixed stops.
func (a *Agent) ReportHostChecks(now time.Time) int {
	root := a.cfg.HostRoot
	if root == "" {
		root = "/"
	}
	findings := hostcheck.Run(root, a.cfg.Facts.ComputeKind)
	day := now.UTC().Format("2006-01-02")
	for _, f := range findings {
		sum := sha256.Sum256([]byte(a.cfg.SensorKey + "|" + f.ID + "|" + f.Detail + "|" + day))
		a.Enqueue(uplink.Event{
			EventKey:    hex.EncodeToString(sum[:16]),
			RuleTable:   "host_check",
			RuleUUID:    f.ID,
			Lane:        "cis",
			SubjectKind: "file",
			Subject:     f.Path,
			Action:      "allowed",
			Detail:      map[string]any{"title": f.Title, "detail": f.Detail, "fix": f.Fix, "severity": f.Severity},
			ObservedAt:  now.UnixMilli(),
		})
	}

	return len(findings)
}

// noteAddonDenial logs, once while it lasts, that the platform refused a call
// for want of an add-on, naming the add-on and what the sensor does meanwhile.
// It reports whether err was such a denial. The caller has already kept its
// state: a denial is never a reason to drop events or apply an empty answer.
func (a *Agent) noteAddonDenial(err error, what, consequence string) bool {
	if !addongate.Is(err) {
		return false
	}
	a.mu.Lock()
	first := !a.addonNoted
	a.addonNoted = true
	a.mu.Unlock()
	if first {
		a.cfg.Logf("sensor: %s refused: %v. %s until the add-on is active", what, err, strings.ToUpper(consequence[:1])+consequence[1:])
	}

	return true
}

func (a *Agent) clearAddonDenial() {
	a.mu.Lock()
	a.addonNoted = false
	a.mu.Unlock()
}
