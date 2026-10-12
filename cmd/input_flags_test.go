package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

func TestDetectInputReadsEveryKind(t *testing.T) {
	dir := t.TempDir()
	tagFile := filepath.Join(dir, "log4j.swidtag")
	tag := `<SoftwareIdentity name="log4j" version="2.14.1"><Entity name="Apache" role="softwareCreator"/></SoftwareIdentity>`
	if err := os.WriteFile(tagFile, []byte(tag+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		arg  string
		want vdb.Inputs
	}{
		{"CVE-2021-44228", vdb.Inputs{VulnIDs: []string{"CVE-2021-44228"}}},
		{"ghsa-jfh8-c2jp-5v3q", vdb.Inputs{VulnIDs: []string{"ghsa-jfh8-c2jp-5v3q"}}},
		{"PYSEC-2021-19", vdb.Inputs{VulnIDs: []string{"PYSEC-2021-19"}}},
		{"pkg:npm/lodash@4.17.20", vdb.Inputs{PURL: "pkg:npm/lodash@4.17.20"}},
		{"PKG:npm/lodash", vdb.Inputs{PURL: "PKG:npm/lodash"}},
		{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", vdb.Inputs{CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}},
		{"cpe:/a:apache:http_server:2.4.49", vdb.Inputs{CPE: "cpe:/a:apache:http_server:2.4.49"}},
		{"urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20", vdb.Inputs{TEI: "urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20"}},
		{"urn%3Atei%3Auuid%3Avulnetix.com%3Ax", vdb.Inputs{TEI: "urn%3Atei%3Auuid%3Avulnetix.com%3Ax"}},
		{tag, vdb.Inputs{SWID: tag}},
		{tagFile, vdb.Inputs{SWID: tag}},
		{`{"vendor":"apache","product":"log4j","version":"2.14.1"}`, vdb.Inputs{Vendor: "apache", Product: "log4j", Version: "2.14.1"}},
	}
	for _, c := range cases {
		got, err := detectInput(c.arg)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("detectInput(%q) = %+v %v, want %+v", c.arg, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "lodash", "2021-44228", "{not json", filepath.Join(dir, "missing.xml")} {
		if _, err := detectInput(bad); err == nil {
			t.Errorf("detectInput(%q) should fail", bad)
		}
	}
}

func TestInputFlagsReadSWIDFromFileStdinOrInline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tag.xml")
	tag := `<SoftwareIdentity name="x" version="1"/>`
	_ = os.WriteFile(path, []byte(tag), 0o644)

	for name, c := range map[string]struct {
		flag  string
		stdin string
		want  string
	}{
		"file":         {path, "", tag},
		"stdin":        {"-", tag + "\n", tag},
		"inline":       {tag, "", tag},
		"base64 value": {"PFNvZnR3YXJlSWRlbnRpdHkgbmFtZT0ieCIvPg==", "", "PFNvZnR3YXJlSWRlbnRpdHkgbmFtZT0ieCIvPg=="},
	} {
		f := inputFlags{swid: c.flag, purl: " pkg:npm/x@1 ", vulnIDs: []string{" CVE-2021-1 ", ""}}
		in, err := f.inputs(strings.NewReader(c.stdin))
		if err != nil || in.SWID != c.want || in.PURL != "pkg:npm/x@1" || !reflect.DeepEqual(in.VulnIDs, []string{"CVE-2021-1"}) {
			t.Errorf("%s: %+v %v", name, in, err)
		}
	}
}

func TestMergeInputsLaysFlagsOverTheArgument(t *testing.T) {
	got := mergeInputs(vdb.Inputs{PURL: "pkg:npm/lodash", VulnIDs: []string{"CVE-1"}},
		vdb.Inputs{Version: "4.17.20", VulnIDs: []string{"CVE-2"}})
	want := vdb.Inputs{PURL: "pkg:npm/lodash", Version: "4.17.20", VulnIDs: []string{"CVE-1", "CVE-2"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merge = %+v", got)
	}
}

func TestPathIdentifierOnlyForOneRoutableInput(t *testing.T) {
	cases := []struct {
		in vdb.Inputs
		id string
		ok bool
	}{
		{vdb.Inputs{VulnIDs: []string{"CVE-2021-44228"}}, "CVE-2021-44228", true},
		{vdb.Inputs{PURL: "pkg:npm/lodash@1"}, "pkg:npm/lodash@1", true},
		{vdb.Inputs{CPE: "cpe:/a:x:y:1"}, "cpe:/a:x:y:1", true},
		{vdb.Inputs{TEI: "urn:tei:purl:x:pkg:npm/y"}, "urn:tei:purl:x:pkg:npm/y", true},
		{vdb.Inputs{VulnIDs: []string{"CVE-1", "CVE-2"}}, "", false},
		{vdb.Inputs{PURL: "pkg:npm/lodash", Version: "1"}, "", false},
		{vdb.Inputs{SWID: "<x/>"}, "", false},
		{vdb.Inputs{CEL: "true"}, "", false},
		{vdb.Inputs{Vendor: "a", Product: "b"}, "", false},
	}
	for _, c := range cases {
		id, ok := pathIdentifier(c.in)
		if id != c.id || ok != c.ok {
			t.Errorf("pathIdentifier(%+v) = %q %v", c.in, id, ok)
		}
	}
}

func TestReadInputLines(t *testing.T) {
	text := strings.Join([]string{
		"# inputs for a weekly check",
		"CVE-2024-3400",
		"",
		"pkg:npm/lodash@4.17.20",
		`{"key":"log4j","vendor":"apache","product":"log4j","version":"2.14.1"}`,
		`{"purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}`,
	}, "\n")
	items, err := readInputLines(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, it := range items {
		keys = append(keys, it.Key)
	}
	want := []string{"CVE-2024-3400", "pkg:npm/lodash@4.17.20", "log4j", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	if items[2].Vendor != "apache" || items[0].VulnIDs[0] != "CVE-2024-3400" {
		t.Errorf("items = %+v", items)
	}
	if _, err := readInputLines(strings.NewReader("lodash\n")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("an unreadable line must be reported by number: %v", err)
	}
}

func TestByKindSummaryIsSorted(t *testing.T) {
	if got := byKindSummary(map[string]int{"SNORT": 2, "AWS_WAF": 1}); got != " (AWS_WAF 1 · SNORT 2)" {
		t.Errorf("summary = %q", got)
	}
	if byKindSummary(nil) != "" {
		t.Error("no kinds, no summary")
	}
}

// -o names a format as it does across vdb; only other values are file paths.
func TestDefenceOutputFlagIsAFormatBeforeItIsAPath(t *testing.T) {
	for _, tc := range []struct{ in, format, path string }{
		{"", "", ""},
		{"json", "json", ""},
		{"JSON", "json", ""},
		{"pretty", "pretty", ""},
		{"table", "table", ""},
		{"rules.json", "", "rules.json"},
		{"out/counts.txt", "", "out/counts.txt"},
	} {
		f := defenceFlags{output: tc.in}
		if format, path := f.target(); format != tc.format || path != tc.path {
			t.Errorf("-o %q: got (%q, %q), want (%q, %q)", tc.in, format, path, tc.format, tc.path)
		}
	}
}

// The upgrade note shows only when the withheld defence lists hold something.
func TestCountsTotalDecidesTheUpgradeNote(t *testing.T) {
	empty := &vdb.DefenceCountsResponse{Items: []vdb.DefenceCountsResult{{VirtualPatches: &vdb.DefenceLaneCounts{}}}}
	if countsTotal(empty, "virtual-patches") != 0 {
		t.Error("an empty lane must total 0")
	}
	some := &vdb.DefenceCountsResponse{Items: []vdb.DefenceCountsResult{{Countermeasures: &vdb.DefenceLaneCounts{Total: 3}}, {}}}
	if countsTotal(some, "countermeasures") != 3 || countsTotal(some, "virtual-patches") != 0 {
		t.Error("totals are per lane")
	}
}
