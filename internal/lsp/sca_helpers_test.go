package lsp

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/vulnetix/cli/v4/internal/lsp/protocol"
	"github.com/vulnetix/cli/v4/internal/scan"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

func TestIsTransientSCAErr(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"429", &vdb.CliAPIError{StatusCode: 429}, true},
		{"500", &vdb.CliAPIError{StatusCode: 500}, true},
		{"503 wrapped", fmt.Errorf("batch: %w", &vdb.CliAPIError{StatusCode: 503}), true},
		{"400", &vdb.CliAPIError{StatusCode: 400}, false},
		{"403", &vdb.CliAPIError{StatusCode: 403}, false},
		{"not found", &vdb.NotFoundError{Message: "gone"}, false},
		{"deadline", fmt.Errorf("call: %w", context.DeadlineExceeded), true},
		{"cancelled", fmt.Errorf("call: %w", context.Canceled), false},
		{"transport", errors.New("failed to execute request: connection reset"), true},
		{"decode", errors.New("invalid character '<' looking for beginning of value"), false},
	} {
		if got := isTransientSCAErr(tt.err); got != tt.want {
			t.Errorf("%s: isTransientSCAErr = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestBackoffFor(t *testing.T) {
	for round, want := range map[int]time.Duration{
		-3: scaBackoffBase,
		0:  scaBackoffBase,
		1:  2 * scaBackoffBase,
		2:  4 * scaBackoffBase,
		3:  scaBackoffMax,
		10: scaBackoffMax,
	} {
		if got := backoffFor(round); got != want {
			t.Errorf("backoffFor(%d) = %s, want %s", round, got, want)
		}
	}
}

func TestCountBySeverityAndDescribeCounts(t *testing.T) {
	diags := map[string][]protocol.Diagnostic{
		"file:///a.go": {{Severity: protocol.SeverityError}, {Severity: protocol.SeverityWarning}, {Severity: protocol.SeverityInformation}},
		"file:///b.go": {{Severity: protocol.SeverityError}, {Severity: protocol.SeverityHint}},
		"file:///c.go": nil,
	}
	counts := CountBySeverity(diags)
	if want := map[string]int{"error": 2, "warning": 1, "info": 2}; !reflect.DeepEqual(counts, want) {
		t.Errorf("CountBySeverity = %v, want %v", counts, want)
	}
	if got := DescribeCounts(counts); got != "2 error(s), 1 warning(s), 2 note(s)" {
		t.Errorf("DescribeCounts = %q", got)
	}
	if got := DescribeCounts(CountBySeverity(nil)); got != "no findings" {
		t.Errorf("DescribeCounts(empty) = %q", got)
	}
	if got := DescribeCounts(map[string]int{"warning": 3}); got != "0 error(s), 3 warning(s), 0 note(s)" {
		t.Errorf("DescribeCounts(warnings only) = %q", got)
	}
}

func TestFlattenPackagesIsInPathOrder(t *testing.T) {
	byFile := map[string][]scan.ScopedPackage{
		"web/package.json": {{Name: "react"}, {Name: "lodash"}},
		"api/go.mod":       {{Name: "chi"}},
		"z/Cargo.toml":     nil,
	}
	var names []string
	for range 5 {
		names = names[:0]
		for _, p := range flattenPackages(byFile) {
			names = append(names, p.Name)
		}
		if want := []string{"chi", "react", "lodash"}; !reflect.DeepEqual(names, want) {
			t.Fatalf("flattenPackages order = %v, want %v", names, want)
		}
	}
}

func TestBuildPurlsIsIndexAlignedAndDeduplicated(t *testing.T) {
	pkgs := []scan.ScopedPackage{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
		{Name: "", Version: "", Ecosystem: ""},
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
		{Name: "requests", Version: "2.19.1", Ecosystem: "pypi"},
	}
	byIndex, unique := buildPurls(pkgs)
	if len(byIndex) != len(pkgs) {
		t.Fatalf("byIndex has %d entries for %d packages", len(byIndex), len(pkgs))
	}
	if byIndex[0] == "" || byIndex[0] != byIndex[2] {
		t.Errorf("the same package must get the same purl at its own index: %v", byIndex)
	}
	if len(unique) != 2 || unique[0] != byIndex[0] || unique[1] != byIndex[3] {
		t.Errorf("unique = %v, want each non-empty purl once in first-seen order (byIndex %v)", unique, byIndex)
	}
	for _, u := range unique {
		if u == "" {
			t.Errorf("an empty purl is never requested: %v", unique)
		}
	}
}

func TestCountVulnerable(t *testing.T) {
	verdicts := map[string]*scaVerdict{
		"a": {Vulns: []scan.EnrichedVuln{{}}},
		"b": {},
		"c": {Vulns: []scan.EnrichedVuln{{}, {}}},
	}
	if got := countVulnerable(verdicts); got != 2 {
		t.Errorf("countVulnerable = %d, want 2", got)
	}
	if got := countVulnerable(nil); got != 0 {
		t.Errorf("countVulnerable(nil) = %d", got)
	}
}
