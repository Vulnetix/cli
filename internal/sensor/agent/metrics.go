package agent

import (
	"runtime"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/internal/sysinv"
)

// passes records how each periodic piece of work last went, for the metrics
// the heartbeat carries: a sensor whose inventory takes a minute, or whose feed
// fetch has failed since Tuesday, says so instead of looking merely quiet.
type passes struct {
	mu    sync.Mutex
	stats map[string]uplink.PassStat
}

func (p *passes) record(name string, start time.Time, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stats == nil {
		p.stats = map[string]uplink.PassStat{}
	}
	s := p.stats[name]
	s.LastAt = start.UnixMilli()
	s.DurationMs = time.Since(start).Milliseconds()
	s.OK = err == nil
	s.Error = ""
	if err != nil {
		s.Error = err.Error()
		if len(s.Error) > 200 {
			s.Error = s.Error[:200]
		}
		s.Failures++
	}
	s.Runs++
	p.stats[name] = s
}

func (p *passes) snapshot() map[string]uplink.PassStat {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]uplink.PassStat, len(p.stats))
	for k, v := range p.stats {
		out[k] = v
	}

	return out
}

// metrics is what the sensor costs the host and how its work is going. It is
// read every heartbeat, so it stays cheap: one getrusage, one small /proc read
// and runtime.ReadMemStats.
func (a *Agent) metrics(now time.Time) *uplink.Metrics {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	cpu, rss := selfUsage()

	return &uplink.Metrics{
		StartedAt:  a.started.UnixMilli(),
		UptimeSec:  int64(now.Sub(a.started).Seconds()),
		CPUSec:     cpu,
		RSSBytes:   rss,
		HeapBytes:  ms.HeapAlloc,
		SysBytes:   ms.Sys,
		Goroutines: runtime.NumGoroutine(),
		NumGC:      ms.NumGC,
		Passes:     a.passes.snapshot(),
	}
}

// flushDue is whether the flush ticker should post now: always, unless the last
// post failed and its backoff has not run out. Shutdown flushes regardless.
func (a *Agent) flushDue(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	return !now.Before(a.flushAfter)
}

// flushBackoff is 5s doubled per consecutive failure, at most 5 minutes.
func flushBackoff(fails int) time.Duration {
	d := 5 * time.Second
	for i := 1; i < fails && d < 5*time.Minute; i++ {
		d *= 2
	}

	return min(d, 5*time.Minute)
}

// withInstalled adds every installed OS package no process maps, as state
// "installed", so the site holds the host's whole package list (what a host
// SBOM is built from) and not only what is loaded. A package already reported
// as loaded keeps that state.
func withInstalled(loaded []uplink.InventoryPackage, installed []sysinv.Package) []uplink.InventoryPackage {
	seen := make(map[string]bool, len(loaded))
	for _, p := range loaded {
		seen[p.Ecosystem+"|"+p.Name] = true
	}
	for _, p := range installed {
		if p.Name == "" || seen[p.Ecosystem+"|"+p.Name] {
			continue
		}
		seen[p.Ecosystem+"|"+p.Name] = true
		loaded = append(loaded, uplink.InventoryPackage{
			Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, State: "installed",
		})
	}

	return loaded
}
