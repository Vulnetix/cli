package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/uplink"
	"github.com/vulnetix/cli/v4/internal/sysinv"
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
	got := withInstalled(loaded, sysinv.Result{Packages: []sysinv.Package{
		{Name: "openssl", Version: "3.2.1-1", Ecosystem: "arch"},
		{Name: "vim", Version: "9.1-1", Ecosystem: "arch"},
		{Name: "vim", Version: "9.1-1", Ecosystem: "arch"},
		{Name: "", Version: "1", Ecosystem: "arch"},
	}})
	if len(got) != 2 || got[0].State != "loaded" || got[1].Name != "vim" || got[1].State != "installed" {
		t.Fatalf("got %+v", got)
	}
}

func TestInventoryCarriesTheHostsRealPurl(t *testing.T) {
	epoch := 1
	sys := sysinv.Result{
		Distro: sysinv.Distro{ID: "amzn", VersionID: "2023"},
		Packages: []sysinv.Package{
			{Name: "openssl-libs", Version: "3.0.8-1.amzn2023.0.12", Ecosystem: "rpm", Arch: "x86_64", Epoch: &epoch, SourceName: "openssl"},
			{Name: "bash", Version: "5.2.15-1.amzn2023", Ecosystem: "rpm", Arch: "x86_64"},
		},
	}
	loaded := []uplink.InventoryPackage{{Name: "openssl-libs", Version: "3.0.8-1.amzn2023.0.12", Ecosystem: "rpm", State: "loaded"}}
	got := withInstalled(loaded, sys)
	want := map[string]string{
		"openssl-libs": "pkg:rpm/amazon/openssl-libs@3.0.8-1.amzn2023.0.12?arch=x86_64&distro=amazon-2023&epoch=1&upstream=openssl",
		"bash":         "pkg:rpm/amazon/bash@5.2.15-1.amzn2023?arch=x86_64&distro=amazon-2023",
	}
	for _, p := range got {
		if p.Purl != want[p.Name] {
			t.Errorf("%s: purl %q, want %q", p.Name, p.Purl, want[p.Name])
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	// A loaded package the OS database does not list has no purl, and says so
	// rather than guessing one.
	if got := withInstalled([]uplink.InventoryPackage{{Name: "ghost", Version: "1", Ecosystem: "rpm", State: "loaded"}}, sys); got[0].Purl != "" {
		t.Fatalf("a package the OS does not list got a purl: %q", got[0].Purl)
	}
}

func TestInventoryReportCompleteness(t *testing.T) {
	pkgs := []uplink.InventoryPackage{{Name: "a"}}
	read := sysinv.Result{Packages: []sysinv.Package{{Name: "a"}}}
	if r := inventoryReport(pkgs, read, 0, 0); r.Complete == nil || !*r.Complete || len(r.Warnings) != 0 {
		t.Errorf("full read = %+v", r)
	}
	broken := sysinv.Result{Packages: read.Packages, Warnings: []string{"var/lib/rpm/Packages: locked"}}
	if r := inventoryReport(pkgs, broken, 0, 0); r.Complete == nil || *r.Complete || len(r.Warnings) != 1 {
		t.Errorf("partial read = %+v", r)
	}
	if r := inventoryReport(nil, sysinv.Result{Unsupported: "NixOS"}, 0, 0); r.Unsupported != "NixOS" || r.Complete != nil {
		t.Errorf("unsupported = %+v", r)
	}
	if r := inventoryReport(nil, sysinv.Result{}, 0, 0); r.Complete != nil {
		t.Errorf("nothing read must leave the site to judge: %+v", r)
	}
	if r := inventoryReport(pkgs, read, 3, 0); r.Complete == nil || !*r.Complete || len(r.Warnings) != 1 {
		t.Errorf("unreadable processes = %+v; a warning, not incomplete", r)
	}
}

func TestWithInstalledKeepsEachArchAndTheNewVersion(t *testing.T) {
	sys := sysinv.Result{Packages: []sysinv.Package{
		{Name: "libc6", Version: "2.36-9", Arch: "amd64", Ecosystem: "deb"},
		{Name: "libc6", Version: "2.36-9", Arch: "i386", Ecosystem: "deb"},
		{Name: "openssl", Version: "3.0.15-1", Arch: "amd64", Ecosystem: "deb"},
	}}
	loaded := []uplink.InventoryPackage{
		{Name: "libc6", Version: "2.36-9", Ecosystem: "deb", State: "loaded"},
		// A process still maps the openssl that was upgraded away.
		{Name: "openssl", Version: "3.0.11-1", Ecosystem: "deb", State: "stale-loaded"},
	}
	out := withInstalled(loaded, sys)
	got := map[string]string{}
	for _, p := range out {
		got[p.Name+"@"+p.Version+"/"+p.Arch] = p.State
	}
	want := map[string]string{
		"libc6@2.36-9/amd64":     "loaded",
		"libc6@2.36-9/i386":      "installed",
		"openssl@3.0.11-1/":      "stale-loaded",
		"openssl@3.0.15-1/amd64": "installed",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestFirstFiles(t *testing.T) {
	if got := firstFiles([]string{"a", "b", "c"}, 2); len(got) != 2 || got[1] != "b" {
		t.Errorf("firstFiles = %v", got)
	}
	if got := firstFiles(nil, 5); got != nil {
		t.Errorf("firstFiles(nil) = %v", got)
	}
}
