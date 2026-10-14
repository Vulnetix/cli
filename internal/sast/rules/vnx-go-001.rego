# SPDX-License-Identifier: Apache-2.0
# Go - missing go.sum

package vulnetix.rules.vnx_go_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-001",
	"name": "Missing go.sum",
	"description": "A go.mod that requires at least one module fetched from outside the repository has no go.sum beside it, or a .gitignore between the repository root and the module excludes go.sum, so the checksums that pin each dependency are never committed and every build resolves whatever the module proxy serves. Reported once per go.mod, on its first require directive. Not reported: a go.sum present in the module directory, a module with no require directive (a standard-library-only module never gets a go.sum), a module whose every requirement is replaced by a local directory (directory replacements are not checksummed), a go.mod under testdata, fixture or test directories (inputs to tests, which the go command ignores), and a require directive that is only a comment.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-001/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["supply-chain", "lockfile", "integrity"],
}

_is_gomod(path) if path == "go.mod"

_is_gomod(path) if endswith(path, "/go.mod")

# The module directory, in file_set key form ("" for the scan root).
_dir(path) := "" if path == "go.mod"

_dir(path) := substring(path, 0, count(path) - count("/go.mod")) if endswith(path, "/go.mod")

_sum_path("") := "go.sum"

_sum_path(dir) := concat("/", [dir, "go.sum"]) if dir != ""

# Module paths named in require directives: single-line and parenthesised
# blocks. Comment text never matches, since every pattern is anchored at the
# start of a line.
_required(content) := {m |
	some hit in regex.find_all_string_submatch_n(`(?m)^[ \t]*require[ \t]+([^\s()/][^\s()]*)[ \t]+v\S+`, content, -1)
	m := hit[1]
} | {m |
	some block in regex.find_all_string_submatch_n(`(?ms)^[ \t]*require[ \t]*\([ \t]*(?://[^\n]*)?\n(.*?)^[ \t]*\)`, content, -1)
	some hit in regex.find_all_string_submatch_n(`(?m)^[ \t]*([^\s/][^\s]*)[ \t]+v\S+`, block[1], -1)
	m := hit[1]
}

# Module paths replaced by a local directory (./x, ../x or an absolute path).
_local_replaced(content) := {m |
	some hit in regex.find_all_string_submatch_n(`(?m)^[ \t]*replace[ \t]+(\S+)(?:[ \t]+v\S+)?[ \t]*=>[ \t]*(?:\.\.?/|/)`, content, -1)
	m := hit[1]
} | {m |
	some block in regex.find_all_string_submatch_n(`(?ms)^[ \t]*replace[ \t]*\([ \t]*(?://[^\n]*)?\n(.*?)^[ \t]*\)`, content, -1)
	some hit in regex.find_all_string_submatch_n(`(?m)^[ \t]*([^\s/]\S*)(?:[ \t]+v\S+)?[ \t]*=>[ \t]*(?:\.\.?/|/)`, block[1], -1)
	m := hit[1]
}

# A .gitignore in the module directory or above it that excludes go.sum. An
# anchored pattern (/go.sum) applies only to the directory of that .gitignore.
_gitignored(dir) if {
	some gi, text in input.file_contents
	_is_gitignore(gi)
	gdir := _gi_dir(gi)
	_ancestor_or_self(gdir, dir)
	not regex.match(`(?m)^[ \t]*!.*go\.sum[ \t]*$`, text)
	_ignores(text, gdir, dir)
}

_is_gitignore(p) if p == ".gitignore"

_is_gitignore(p) if endswith(p, "/.gitignore")

_gi_dir(".gitignore") := ""

_gi_dir(p) := substring(p, 0, count(p) - count("/.gitignore")) if endswith(p, "/.gitignore")

_ancestor_or_self("", _) := true

_ancestor_or_self(g, d) if {
	g != ""
	g == d
}

_ancestor_or_self(g, d) if {
	g != ""
	startswith(d, concat("", [g, "/"]))
}

# Unanchored: matches go.sum at any depth below the .gitignore.
_ignores(text, _, _) if regex.match(`(?m)^[ \t]*(?:\*\*/)?(?:go\.sum|\*\.sum)[ \t]*$`, text)

# Anchored to the .gitignore's own directory.
_ignores(text, gdir, dir) if {
	gdir == dir
	regex.match(`(?m)^[ \t]*/go\.sum[ \t]*$`, text)
}

_unpinned(dir) if not input.file_set[_sum_path(dir)]

_unpinned(dir) if _gitignored(dir)

findings contains finding if {
	some path, content in input.file_contents
	_is_gomod(path)
	contains(content, "require")
	not helpers.is_test_path(path)
	external := _required(content) - _local_replaced(content)
	count(external) > 0
	dir := _dir(path)
	_unpinned(dir)
	lines := split(content, "\n")
	first := min([i | some i, l in lines; regex.match(`^[ \t]*require\b`, l)])
	finding := {
		"rule_id": metadata.id,
		"message": "go.mod requires external modules but no committed go.sum pins their checksums; run 'go mod tidy' and commit go.sum",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": first + 1,
		"snippet": lines[first],
	}
}
