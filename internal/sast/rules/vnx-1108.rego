# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1108

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1108",
	"name": "Excessive Reliance on Global Variables",
	"description": "A Python or PHP module relies on mutable global state from inside its functions to an excessive degree: the file contains three or more `global` statements (Python `global name`, PHP `global $name`), or a single `global` statement that rebinds four or more names. Functions coupled through shared globals cannot be reasoned about or tested in isolation, and in a long-lived web worker the values leak between requests and users. Reported: each `global` statement in such a file. Not reported: a file with one or two narrow `global` statements (the lazy singleton or module cache), the word global in strings, docstrings and comments, identifiers such as global_counter or GLOBAL_TIMEOUT, nonlocal, $GLOBALS array access, PHP statements that name only WordPress core globals ($wpdb, $post, $wp_query and the like, which WordPress exposes only that way), global statements shown as examples inside Python docstrings, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1108/",
	"languages": ["python", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1108],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["maintainability", "global-state", "cwe-1108"],
}

_stmt_re(path) := `^\s+global\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?:#.*)?$` if endswith(path, ".py")

_stmt_re(path) := `^\s*global\s+(\$[A-Za-z_]\w*(?:\s*,\s*\$[A-Za-z_]\w*)*)\s*;` if endswith(path, ".php")

findings contains finding if {
	some path, content in input.file_contents
	re := _stmt_re(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*global\s+[$A-Za-z_]`, content)
	lines := split(content, "\n")
	stmts := [[i, count(split(m[0][1], ","))] |
		some i, l in lines
		contains(l, "global")
		m := regex.find_all_string_submatch_n(re, l, 1)
		count(m) > 0
		not _in_py_string(path, lines, i)
		not _framework_only(path, m[0][1])
	]
	some s in stmts
	_excessive(stmts)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This module rebinds global variables from %d global statement(s); pass state explicitly (parameters, a class or a context object) instead of coupling functions through module globals", [count(stmts)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": s[0] + 1,
		"snippet": lines[s[0]],
	}
}

_excessive(stmts) if count(stmts) >= 3

_excessive(stmts) if {
	some s in stmts
	s[1] >= 4
}

# A Python line inside a triple-quoted string (a docstring showing an
# example): an odd number of triple quotes opened above it. Only computed
# for the few lines that look like a global statement.
_in_py_string(path, lines, i) if {
	endswith(path, ".py")
	n := count(regex.find_all_string_submatch_n(`"""|'''`, concat("\n", array.slice(lines, 0, i)), -1))
	n % 2 == 1
}

# WordPress hands plugins its core objects only as globals ($wpdb, $post,
# $wp_query, ...): naming them is the framework's API, not the module's own
# shared state. A statement that also names the module's globals still counts.
_wp_globals := {
	"$wpdb", "$post", "$wp_query", "$wp", "$wp_rewrite", "$wp_version", "$pagenow",
	"$current_user", "$wp_roles", "$wp_filesystem", "$wp_scripts", "$wp_styles",
	"$wp_locale", "$wp_admin_bar", "$typenow", "$current_screen", "$wp_embed",
	"$wp_customize", "$wp_post_types", "$wp_taxonomies", "$wp_the_query",
}

_framework_only(path, names) if {
	endswith(path, ".php")
	every n in split(names, ",") {
		trim_space(n) in _wp_globals
	}
}
