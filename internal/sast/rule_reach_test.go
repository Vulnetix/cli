package sast

import (
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const reachHelpers = `package vulnetix.helpers

import rego.v1

is_comment_line(line) if startswith(trim_space(line), "#")

config_values(key) := {v |
	some p, c in input.file_contents
	endswith(p, ".properties")
	some v in regex.find_all_string_submatch_n(key, c, -1)
}

has_go if input.file_set["go.mod"]
`

func reachOf(t *testing.T, rule string) moduleReach {
	t.Helper()
	got := classifyReach(map[string]string{"helpers.rego": reachHelpers, "rule.rego": rule})
	r, ok := got["rule.rego"]
	require.True(t, ok, "rule.rego was not classified")
	return r
}

func TestClassifyReach(t *testing.T) {
	cases := []struct {
		name string
		rule string
		want moduleReach
	}{
		{"one file at a time", `package vulnetix.rules.a
import rego.v1
import data.vulnetix.helpers
findings contains f if {
	some path, content in input.file_contents
	some i, line in split(content, "\n")
	not helpers.is_comment_line(line)
	contains(line, "eval(")
	f := {"artifact_uri": path, "start_line": i + 1}
}`, moduleReach{perFile: true}},
		{"several independent bodies", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	some path, content in input.file_contents
	contains(content, "a")
	f := {"artifact_uri": path}
}
findings contains f if {
	some path
	content := input.file_contents[path]
	contains(content, "b")
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true}},
		{"a guard that reads every file", `package vulnetix.rules.a
import rego.v1
_uses_flask if {
	some _, c in input.file_contents
	contains(c, "flask")
}
findings contains f if {
	_uses_flask
	some path, content in input.file_contents
	f := {"artifact_uri": path}
}`, moduleReach{}},
		{"two files in one body", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	some path, content in input.file_contents
	some other, c2 in input.file_contents
	other != path
	f := {"artifact_uri": path}
}`, moduleReach{}},
		{"an aggregate over files", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	n := count([p | some p, _ in input.file_contents])
	n > 100
	f := {"artifact_uri": "."}
}`, moduleReach{}},
		{"a literal path", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	c := input.file_contents["Dockerfile"]
	contains(c, "ADD")
	f := {"artifact_uri": "Dockerfile"}
}`, moduleReach{}},
		{"a helper that reads other files", `package vulnetix.rules.a
import rego.v1
import data.vulnetix.helpers
findings contains f if {
	some path, content in input.file_contents
	some v in helpers.config_values("password")
	contains(content, v)
	f := {"artifact_uri": path}
}`, moduleReach{}},
		{"the file list", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	input.file_set["go.sum"]
	some path, content in input.file_contents
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, usesTree: true}},
		{"the file list through a helper", `package vulnetix.rules.a
import rego.v1
import data.vulnetix.helpers
findings contains f if {
	helpers.has_go
	some path, content in input.file_contents
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, usesTree: true}},
		{"the whole input", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	walk(input, [p, v])
	some path, content in input.file_contents
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, usesTree: true}},
		{"no file contents", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	input.file_set["package-lock.json"]
	f := {"artifact_uri": "package-lock.json"}
}`, moduleReach{usesTree: true}},
		{"the clock", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	some path, content in input.file_contents
	to_number(content) < time.now_ns()
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, volatile: true}},
		{"the clock through a rule in the same package", `package vulnetix.rules.a
import rego.v1
_expired(exp) if exp * 1000000000 < time.now_ns()
findings contains f if {
	some path, content in input.file_contents
	_expired(to_number(content))
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, volatile: true}},
		{"a validity check that reads the clock", `package vulnetix.rules.a
import rego.v1
findings contains f if {
	some path, content in input.file_contents
	[valid, _, _] := io.jwt.decode_verify(content, {"secret": "s"})
	valid
	f := {"artifact_uri": path}
}`, moduleReach{perFile: true, volatile: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, reachOf(t, c.rule))
		})
	}
}

func TestClassifyReachUnparseableIsLeftOut(t *testing.T) {
	got := classifyReach(map[string]string{"bad.rego": "package vulnetix.rules.bad\nfindings contains f if {"})
	_, ok := got["bad.rego"]
	require.False(t, ok)
}

// The embedded rules, as a tally, so a change in how many run per file is
// visible in review.
func TestClassifyReachEmbedded(t *testing.T) {
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)
	modules = FilterModulesToKinds(modules, []string{"sast"})
	reach := classifyReach(modules)
	var perFile, cacheable, total int
	for _, r := range reach {
		total++
		if r.perFile {
			perFile++
			if !r.usesTree {
				cacheable++
			}
		}
	}
	t.Logf("sast rules: %d, per file: %d, per file and cacheable: %d", total, perFile, cacheable)
	require.Greater(t, perFile, total/2, "most sast rules read one file at a time")
}

// A rule whose verdict changes with the clock must not be served from the
// result cache: an unexpired token would stay unexpired forever.
func TestClassifyReachClockRuleIsVolatile(t *testing.T) {
	modules, err := LoadAllModules(DefaultRulesFS, false, nil, "", io.Discard)
	require.NoError(t, err)
	var found bool
	for name, r := range classifyReach(modules) {
		if strings.Contains(modules[name], "package vulnetix.rules.vnx_sec_011\n") {
			found = true
			require.True(t, r.volatile, "%s reads time.now_ns", name)
		}
	}
	require.True(t, found, "vnx-sec-011 is embedded")
}

func TestSharedFor(t *testing.T) {
	shared := map[string]string{
		"helpers.rego": "package vulnetix.helpers\nimport rego.v1\nis_comment_line(l) if startswith(l, \"#\")\n",
		"k8s.rego":     "package lib.k8s\nimport rego.v1\nimport data.lib.common\nis_pod(x) if common.kind(x) == \"Pod\"\n",
		"common.rego":  "package lib.common\nimport rego.v1\nkind(x) := x.kind\n",
		"aws.rego":     "package lib.aws\nimport rego.v1\nregions := {\"us-east-1\"}\n",
		"broken.rego":  "package lib.broken\nthis is not rego",
	}
	rules := map[string]string{
		"rule.rego": "package vulnetix.rules.a\nimport rego.v1\nimport data.vulnetix.helpers\nimport data.lib.k8s\nfindings contains f if { some p, c in input.file_contents; not helpers.is_comment_line(c); k8s.is_pod({}); f := p }\n",
	}
	all := map[string]string{}
	maps.Copy(all, shared)
	maps.Copy(all, rules)
	got := indexModules(all).sharedFor(shared, rules)
	require.ElementsMatch(t, []string{"helpers.rego", "k8s.rego", "common.rego", "broken.rego"}, slices.Collect(maps.Keys(got)),
		"a library the rules never name is left out; one a kept library imports is kept; one that does not parse is kept")

	unparsed := map[string]string{"bad.rego": "package vulnetix.rules.bad\nfindings contains f if {"}
	maps.Copy(all, unparsed)
	require.Len(t, indexModules(all).sharedFor(shared, unparsed), len(shared), "an unparsed rule keeps every shared module")
}
