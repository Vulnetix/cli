package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/internal/sysinv"
)

func TestFlushBackoffDoublesToFiveMinutes(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := flushBackoff(i + 1); got != w {
			t.Errorf("failure %d: got %v want %v", i+1, got, w)
		}
	}
}

func TestFlushDueHonoursBackoff(t *testing.T) {
	a := &Agent{}
	now := time.Now()
	if !a.flushDue(now) {
		t.Fatal("a fresh agent flushes")
	}
	a.flushAfter = now.Add(time.Minute)
	if a.flushDue(now) {
		t.Fatal("inside the backoff it waits")
	}
	if !a.flushDue(now.Add(2 * time.Minute)) {
		t.Fatal("after the backoff it flushes")
	}
}

func TestPassesRecordRunsFailuresAndLastError(t *testing.T) {
	var p passes
	start := time.Now()
	p.record("feeds", start, errors.New("HTTP 503"))
	p.record("feeds", start, nil)
	s := p.snapshot()["feeds"]
	if s.Runs != 2 || s.Failures != 1 || !s.OK || s.Error != "" || s.LastAt != start.UnixMilli() {
		t.Fatalf("got %+v", s)
	}
}

func TestMetricsReportsTheProcess(t *testing.T) {
	a := &Agent{started: time.Now().Add(-90 * time.Second)}
	a.passes.record("inventory", time.Now(), nil)
	m := a.metrics(time.Now())
	if m.UptimeSec < 89 || m.Goroutines == 0 || m.HeapBytes == 0 || m.Passes["inventory"].Runs != 1 {
		t.Fatalf("got %+v", m)
	}
}

func TestWithInstalledAddsWhatNoProcessMaps(t *testing.T) {
	loaded := []uplink.InventoryPackage{{Name: "openssl", Version: "3.2.1-1", Ecosystem: "arch", State: "loaded", Processes: 4}}
	got := withInstalled(loaded, []sysinv.Package{
		{Name: "openssl", Version: "3.2.1-1", Ecosystem: "arch"},
		{Name: "vim", Version: "9.1-1", Ecosystem: "arch"},
		{Name: "vim", Version: "9.1-1", Ecosystem: "arch"},
		{Name: "", Version: "1", Ecosystem: "arch"},
	})
	if len(got) != 2 || got[0].State != "loaded" || got[1].Name != "vim" || got[1].State != "installed" {
		t.Fatalf("got %+v", got)
	}
}
