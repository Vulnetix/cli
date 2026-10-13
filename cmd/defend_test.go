package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/defences"
	"github.com/vulnetix/cli/v3/internal/report"
	"github.com/vulnetix/cli/v3/internal/scanopts"
)

var defendNow = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

func defendSurface() scanopts.Surface {
	return scanopts.Surface{Color: "never", Display: report.Options{Width: 100, ASCII: true}}
}

func defendSource(body string) defences.StaticSource {
	sum := sha256.Sum256([]byte(body))
	rule := defences.Rule{
		UUID: "u1", ArtifactID: "VX-1", Kind: defences.KindModSec, Confidence: "HIGH",
		DeployMode: "log", FalsePositiveRisk: "LOW", ArchiveURL: "/v2/virtual-patches/u1/archive",
		CoverageNotes: "Does not match encoded variants.",
	}
	return defences.StaticSource{
		Summaries: map[string]defences.Summary{"CVE-2025-1": {
			Block: defences.LaneSummary{Count: 1, ByKind: map[defences.Kind]int{defences.KindModSec: 1}, Rules: []defences.Rule{rule}},
		}},
		Bodies: map[string]defences.Body{"u1": {Kind: defences.KindModSec, Content: []byte(body), SHA256: hex.EncodeToString(sum[:])}},
	}
}

func runDefendFor(t *testing.T, o defendOptions, src defences.Source, pro bool) (string, error) {
	t.Helper()
	if o.Root == "" {
		o.Root = t.TempDir()
	}
	if o.Now.IsZero() {
		o.Now = defendNow
	}
	var out bytes.Buffer
	err := runDefend(context.Background(), o, defendSurface(), src, pro, &out, &out)
	return out.String(), err
}

func TestDefendSavesVerifiesAndRecords(t *testing.T) {
	root := t.TempDir()
	out, err := runDefendFor(t, defendOptions{
		Root: root, ID: "CVE-2025-1", For: "modsecurity", OutDir: filepath.Join(root, "defences"),
		Record: "ModSecurity, prod-eu ingress", Until: "2027-01-10", Package: "legacy-xml",
	}, defendSource("SecRule ARGS \"@rx x\" \"id:1\""), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	saved := filepath.Join(root, "defences", "VX-1-modsecurity.conf")
	if b, rerr := os.ReadFile(saved); rerr != nil || !strings.Contains(string(b), "SecRule") {
		t.Fatalf("rule not written: %v", rerr)
	}
	for _, want := range []string{"matches the checksum the database sent", "start in log mode", "recorded", "still affected and still counted", "MONITORED"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	set, err := defences.LoadControls(root)
	if err != nil || len(set.Controls) != 1 {
		t.Fatalf("controls: %v %+v", err, set)
	}
	c := set.Controls[0]
	if c.Lane != defences.LaneBlock || c.Mode != "log" || c.Package != "legacy-xml" || c.Until.Format("2006-01-02") != "2027-01-10" {
		t.Errorf("control = %+v", c)
	}
	if c.Blocks() {
		t.Error("a rule recorded in log mode must not count as blocking")
	}

	vex, err := os.ReadFile(filepath.Join(root, ".vulnetix", "vex-compensating-controls.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"affected"`, "compensating-control: ModSecurity, prod-eu ingress (log only)", "CVE-2025-1"} {
		if !strings.Contains(string(vex), want) {
			t.Errorf("VEX missing %q:\n%s", want, vex)
		}
	}
	if strings.Contains(string(vex), "not_affected") {
		t.Error("a virtual patch never makes a package unaffected")
	}
}

func TestDefendRefusesABodyThatFailsItsChecksum(t *testing.T) {
	root := t.TempDir()
	src := defendSource("good body")
	b := src.Bodies["u1"]
	b.Content = []byte("tampered body")
	src.Bodies["u1"] = b

	_, err := runDefendFor(t, defendOptions{Root: root, ID: "CVE-2025-1", For: "modsecurity", OutDir: filepath.Join(root, "d")}, src, true)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v, want a checksum failure", err)
	}
	if _, serr := os.Stat(filepath.Join(root, "d")); !os.IsNotExist(serr) {
		entries, _ := os.ReadDir(filepath.Join(root, "d"))
		if len(entries) != 0 {
			t.Errorf("a rule that failed its checksum was written: %v", entries)
		}
	}
}

func TestDefendWithoutProShowsCountsAndSavesNothing(t *testing.T) {
	root := t.TempDir()
	out, err := runDefendFor(t, defendOptions{Root: root, ID: "CVE-2025-1", For: "modsecurity", OutDir: filepath.Join(root, "d")}, defendSource("x"), false)
	if err == nil || !strings.Contains(err.Error(), "Pro plan") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "ModSecurity") || !strings.Contains(out, "Pro plan") {
		t.Errorf("the counts and the reason should be shown:\n%s", out)
	}
}

func TestDefendWithTheStubSaysSo(t *testing.T) {
	_, err := runDefendFor(t, defendOptions{ID: "CVE-2025-1", For: "modsecurity"}, defences.Unavailable, true)
	if err == nil || !strings.Contains(err.Error(), "not available in this version yet") {
		t.Fatalf("err = %v", err)
	}
	out, err := runDefendFor(t, defendOptions{ID: "CVE-2025-1"}, defences.Unavailable, true)
	if err != nil || !strings.Contains(out, "not available in this version yet") {
		t.Fatalf("reading with the stub should explain, not fail: %v\n%s", err, out)
	}
}

func TestDefendRecordValidation(t *testing.T) {
	src := defendSource("x")
	for name, c := range map[string]struct {
		o    defendOptions
		want string
	}{
		"no package known":    {defendOptions{ID: "CVE-2025-1", For: "modsecurity", Record: "x"}, "--package"},
		"already expired":     {defendOptions{ID: "CVE-2025-1", For: "modsecurity", Record: "x", Package: "p", Until: "2026-01-01"}, "not in the future"},
		"bad date":            {defendOptions{ID: "CVE-2025-1", For: "modsecurity", Record: "x", Package: "p", Until: "soon"}, "YYYY-MM-DD"},
		"bad mode":            {defendOptions{ID: "CVE-2025-1", For: "modsecurity", Record: "x", Package: "p", Mode: "maybe"}, "block or log"},
		"unknown format":      {defendOptions{ID: "CVE-2025-1", For: "iptables"}, "unknown format"},
		"record needs a lane": {defendOptions{ID: "CVE-2025-1", Record: "x", Package: "p"}, "--for <format> or --lane"},
	} {
		t.Run(name, func(t *testing.T) {
			c.o.OutDir = filepath.Join(t.TempDir(), "d")
			_, err := runDefendFor(t, c.o, src, true)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestDefendRecordsADetectionWithoutAFile(t *testing.T) {
	root := t.TempDir()
	out, err := runDefendFor(t, defendOptions{
		Root: root, ID: "CVE-2025-1", Lane: "detect", Record: "Sigma in the SOC SIEM", Package: "legacy-xml",
	}, defendSource("x"), true)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	set, _ := defences.LoadControls(root)
	if len(set.Controls) != 1 || set.Controls[0].Lane != defences.LaneDetect {
		t.Fatalf("%+v", set)
	}
	if !strings.Contains(out, "stops nothing") {
		t.Errorf("a detection must say it stops nothing:\n%s", out)
	}
}

func TestDefendNotIndexed(t *testing.T) {
	out, err := runDefendFor(t, defendOptions{ID: "NOT AN ID"}, defendSource("x"), true)
	if err != nil || !strings.Contains(out, "Not indexed") {
		t.Fatalf("%v\n%s", err, out)
	}
}
