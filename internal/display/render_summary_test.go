package display

import (
	"reflect"
	"strings"
	"testing"
)

func plainCtx() *Context { return &Context{Term: &Terminal{Width: 100}} }

func fullSummary() map[string]any {
	return map[string]any{
		"database": map[string]any{
			"totalRows": float64(1234567), "distinctCveIds": float64(250000), "totalExploits": float64(42000),
			"maliciousPackages": float64(9000), "cvesWithExploits": float64(31000), "totalReferences": float64(3000000),
			"distinctReferenceUrls": float64(2500000), "totalKev": float64(1200),
		},
		"severity": map[string]any{
			"critical": float64(10), "high": float64(20), "medium": float64(40), "low": float64(20), "none": float64(10),
		},
		"coverage": map[string]any{
			"withCvss": float64(1000), "cvssV2Count": float64(100), "cvssV3Count": float64(800), "cvssV4Count": float64(100),
			"withEpss": float64(900), "withCess": float64(50), "withCwe": float64(700), "withCapec": float64(300),
			"withSsvc": float64(20), "noReferences": float64(5), "averageEpss": 0.123456789, "highEpss": float64(33),
		},
		"enrichment": map[string]any{
			"snortRules": float64(11), "enrichedIDS": float64(12), "patchableAll": float64(13), "patchableCve": float64(14),
			"enrichedCPE": float64(15), "enrichedPURL": float64(16), "enrichedPatchable": float64(17), "enrichedCRIT": float64(18),
		},
		"topCWEs": []any{
			map[string]any{"cweId": "CWE-79", "count": float64(5000)},
			"not a map",
			map[string]any{"cweId": "CWE-89", "count": float64(3000)},
		},
		"topVendors": []any{
			map[string]any{"vendor": "a-vendor-name-that-is-far-too-long-for-the-column", "count": float64(77)},
		},
	}
}

func TestRenderSummaryFullRecord(t *testing.T) {
	out := RenderSummary(fullSummary(), plainCtx())
	for _, want := range []string{
		"VDB Database Summary",
		"Database Coverage", "Total advisories", "1,234,567", "KEV entries", "1,200",
		"Severity Distribution", "Critical", "10.0%", "Medium", "40.0%",
		"Enrichment Coverage", "With CVSS", "Average EPSS", "0.123457", "High EPSS (≥0.7)",
		"Enrichment", "Snort rules", "CRIT records",
		"Top CWEs", "CWE-79", "5,000 advisories", "CWE-89",
		"Top Vendors", "77 advisories",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not a map") {
		t.Errorf("a non-map CWE entry must be skipped:\n%s", out)
	}
	if strings.Contains(out, "a-vendor-name-that-is-far-too-long-for-the-column") {
		t.Errorf("a long vendor name must be truncated to its column:\n%s", out)
	}
}

func TestRenderSummaryMissingSectionsIsHeaderOnly(t *testing.T) {
	out := RenderSummary(map[string]any{"topCWEs": []any{}, "topVendors": "nope"}, plainCtx())
	if !strings.Contains(out, "VDB Database Summary") {
		t.Fatalf("the header is always drawn:\n%s", out)
	}
	for _, absent := range []string{"Database Coverage", "Severity Distribution", "Enrichment", "Top CWEs", "Top Vendors"} {
		if strings.Contains(out, absent) {
			t.Errorf("%q drawn for a record without that section:\n%s", absent, out)
		}
	}
}

func TestRenderSummaryNonMapFallsBackToItsValue(t *testing.T) {
	if got := RenderSummary([]int{1, 2}, plainCtx()); got != "[1 2]" {
		t.Errorf("RenderSummary(non-map) = %q, want %q", got, "[1 2]")
	}
}

// With no counts at all there is nothing to divide by: the rows are drawn
// without a percentage rather than as 0.0% or NaN.
func TestRenderSummaryZeroTotalOmitsPercentages(t *testing.T) {
	out := RenderSummary(map[string]any{"severity": map[string]any{}}, plainCtx())
	if !strings.Contains(out, "Severity Distribution") || !strings.Contains(out, "Critical") {
		t.Fatalf("the severity rows are still drawn:\n%s", out)
	}
	if strings.Contains(out, "%") {
		t.Errorf("no percentage when the total is zero:\n%s", out)
	}
}

func TestRenderStatus(t *testing.T) {
	full := map[string]any{
		"cli": map[string]any{
			"version": "4.24.6", "commit": "abc123", "build_date": "2026-11-01", "go_version": "go1.25",
			"platform": "linux/amd64", "api_version": "v2", "oas_spec_url": "https://api.example/openapi.json",
		},
		"api":  map[string]any{"status": "ok", "region": "ap-southeast-2", "db": "up"},
		"auth": map[string]any{"status": "ok (api key)", "method": "ApiKey", "source": "env", "org_id": "org-1"},
	}
	out := RenderStatus(full, plainCtx())
	for _, want := range []string{
		"VDB Status", "CLI", "4.24.6", "abc123", "linux/amd64", "OpenAPI Spec", "https://api.example/openapi.json",
		"API Health", "ok", "region:", "ap-southeast-2",
		"Authentication", "ApiKey", "Org ID", "org-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status is missing %q:\n%s", want, out)
		}
	}
	// Extra health fields are listed in key order.
	if strings.Index(out, "db:") > strings.Index(out, "region:") {
		t.Errorf("health fields must be sorted:\n%s", out)
	}

	bare := RenderStatus(map[string]any{"cli": map[string]any{"version": "1"}, "auth": map[string]any{"status": "missing"}}, plainCtx())
	for _, absent := range []string{"OpenAPI Spec", "API Health", "Org ID"} {
		if strings.Contains(bare, absent) {
			t.Errorf("%q drawn without its data:\n%s", absent, bare)
		}
	}

	empty := RenderStatus(map[string]any{}, plainCtx())
	if !strings.Contains(empty, "VDB Status") || strings.Contains(empty, "CLI") {
		t.Errorf("an empty status is the header alone:\n%s", empty)
	}

	// A struct goes through its JSON form; a value with no JSON form is printed.
	type cliInfo struct {
		Version string `json:"version"`
	}
	type status struct {
		CLI cliInfo `json:"cli"`
	}
	if out := RenderStatus(status{CLI: cliInfo{Version: "9.9.9"}}, plainCtx()); !strings.Contains(out, "9.9.9") {
		t.Errorf("a struct status is rendered through its JSON tags:\n%s", out)
	}
	if got := RenderStatus(func() {}, plainCtx()); !strings.HasPrefix(got, "0x") {
		t.Errorf("a value with no JSON form falls back to %%v, got %q", got)
	}
}

func TestExtractCVSSPicksTheFirstMetricInPriorityOrder(t *testing.T) {
	metric := func(key string, score float64, sev, vec string) map[string]any {
		return map[string]any{key: map[string]any{"baseScore": score, "baseSeverity": sev, "vectorString": vec}}
	}
	tests := []struct {
		name      string
		container map[string]any
		score     float64
		severity  string
		vector    string
		version   string
	}{
		{"v4", map[string]any{"metrics": []any{metric("cvssV4_0", 9.3, "CRITICAL", "CVSS:4.0/AV:N")}}, 9.3, "CRITICAL", "CVSS:4.0/AV:N", "CVSS 4.0"},
		{"v3.1", map[string]any{"metrics": []any{metric("cvssV3_1", 7.5, "HIGH", "CVSS:3.1/AV:N")}}, 7.5, "HIGH", "CVSS:3.1/AV:N", "CVSS 3.1"},
		{"v3.0", map[string]any{"metrics": []any{metric("cvssV3_0", 5.0, "MEDIUM", "CVSS:3.0/AV:L")}}, 5.0, "MEDIUM", "CVSS:3.0/AV:L", "CVSS 3.0"},
		{"v2", map[string]any{"metrics": []any{metric("cvssV2_0", 4.3, "MEDIUM", "AV:N/AC:M")}}, 4.3, "MEDIUM", "AV:N/AC:M", "CVSS 2.0"},
		{"v4 wins inside one metric", map[string]any{"metrics": []any{map[string]any{
			"cvssV3_1": map[string]any{"baseScore": 7.5, "baseSeverity": "HIGH"},
			"cvssV4_0": map[string]any{"baseScore": 8.7, "baseSeverity": "HIGH"},
		}}}, 8.7, "HIGH", "", "CVSS 4.0"},
		{"first metric with a cvss key wins", map[string]any{"metrics": []any{
			"not a map",
			map[string]any{"other": map[string]any{}},
			metric("cvssV3_1", 6.1, "MEDIUM", "CVSS:3.1/X"),
			metric("cvssV4_0", 9.9, "CRITICAL", "CVSS:4.0/Y"),
		}}, 6.1, "MEDIUM", "CVSS:3.1/X", "CVSS 3.1"},
		{"no metrics", map[string]any{}, 0, "", "", ""},
		{"metrics not a list", map[string]any{"metrics": map[string]any{"cvssV4_0": map[string]any{}}}, 0, "", "", ""},
		{"no cvss key in any metric", map[string]any{"metrics": []any{map[string]any{"other": 1}}}, 0, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var score float64
			var severity, vector, version string
			extractCVSS(tt.container, &score, &severity, &vector, &version)
			if score != tt.score || severity != tt.severity || vector != tt.vector || version != tt.version {
				t.Errorf("got (%v, %q, %q, %q), want (%v, %q, %q, %q)",
					score, severity, vector, version, tt.score, tt.severity, tt.vector, tt.version)
			}
		})
	}
}

// Values already found (from an earlier container) are kept.
func TestExtractCVSSKeepsValuesAlreadySet(t *testing.T) {
	score, severity, vector, version := 5.5, "MEDIUM", "", "CVSS 3.1"
	extractCVSS(map[string]any{"metrics": []any{map[string]any{
		"cvssV4_0": map[string]any{"baseScore": 9.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/Z"},
	}}}, &score, &severity, &vector, &version)
	if score != 5.5 || severity != "MEDIUM" || vector != "CVSS:4.0/Z" || version != "CVSS 3.1" {
		t.Errorf("got (%v, %q, %q, %q)", score, severity, vector, version)
	}
}

func TestExtractCWEsAndRefs(t *testing.T) {
	container := map[string]any{
		"problemTypes": []any{
			map[string]any{"descriptions": []any{
				map[string]any{"cweId": "CWE-79"}, map[string]any{"description": "no id"}, "junk",
			}},
			map[string]any{"descriptions": "not a list"},
			"junk",
			map[string]any{"descriptions": []any{map[string]any{"cweId": "CWE-89"}}},
		},
		"references": []any{
			map[string]any{"url": "https://a"}, "junk", map[string]any{"url": "https://b"},
		},
	}
	if got := extractCWEs(container); !reflect.DeepEqual(got, []string{"CWE-79", "CWE-89"}) {
		t.Errorf("extractCWEs = %v", got)
	}
	refs := extractRefs(container)
	if len(refs) != 2 || refs[0]["url"] != "https://a" || refs[1]["url"] != "https://b" {
		t.Errorf("extractRefs = %v", refs)
	}

	empty := map[string]any{"problemTypes": "x", "references": map[string]any{}}
	if got := extractCWEs(empty); len(got) != 0 {
		t.Errorf("extractCWEs without problemTypes = %v", got)
	}
	if got := extractRefs(empty); len(got) != 0 {
		t.Errorf("extractRefs without references = %v", got)
	}
}

func TestToIntAndToMatchSlice(t *testing.T) {
	for _, tt := range []struct {
		in   any
		want int
	}{{7, 7}, {int64(8), 8}, {float64(9.9), 9}, {"10", 0}, {nil, 0}} {
		if got := toInt(tt.in); got != tt.want {
			t.Errorf("toInt(%#v) = %d, want %d", tt.in, got, tt.want)
		}
	}

	a := map[string]any{"file": "a.go"}
	b := map[string]any{"file": "b.go"}
	if got := toMatchSlice([]any{a, "junk", b}); !reflect.DeepEqual(got, []map[string]any{a, b}) {
		t.Errorf("toMatchSlice([]any) = %v", got)
	}
	typed := []map[string]any{a}
	if got := toMatchSlice(typed); !reflect.DeepEqual(got, typed) {
		t.Errorf("toMatchSlice([]map) = %v", got)
	}
	if got := toMatchSlice("nope"); got != nil {
		t.Errorf("toMatchSlice(other) = %v, want nil", got)
	}
	if got := toMatchSlice([]any{}); got == nil || len(got) != 0 {
		t.Errorf("toMatchSlice(empty) = %#v, want an empty slice", got)
	}
}
