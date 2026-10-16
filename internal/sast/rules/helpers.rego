# SPDX-License-Identifier: Apache-2.0
# Helper functions and templates for SAST rules

package vulnetix.helpers

import rego.v1

# Common language detection functions
_is_lang(path, ext) if endswith(path, ext)

is_c(path) if endswith(path, ".c")

is_cpp(path) if endswith(path, ".cpp")
is_cpp(path) if endswith(path, ".cc")
is_cpp(path) if endswith(path, ".cxx")

is_c_like(path) if is_c(path)
is_c_like(path) if is_cpp(path)

is_go(path) if endswith(path, ".go")
is_java(path) if endswith(path, ".java")
is_js(path) if endswith(path, ".js")
is_ts(path) if endswith(path, ".ts")
is_py(path) if endswith(path, ".py")
is_ruby(path) if endswith(path, ".rb")
is_php(path) if endswith(path, ".php")
is_rust(path) if endswith(path, ".rs")
is_swift(path) if endswith(path, ".swift")
is_kotlin(path) if endswith(path, ".kt")
is_docker(path) if endswith(path, ".dockerfile")
is_docker(path) if endswith(path, ".docker")

is_bash(path) if endswith(path, ".sh")

is_gql(path) if endswith(path, ".graphql")
is_gql(path) if endswith(path, ".gql")
is_tf(path) if endswith(path, ".tf")
is_sql(path) if endswith(path, ".sql")

# Skip patterns for generated/minified files
_should_skip(path) if endswith(path, ".lock")
_should_skip(path) if endswith(path, ".sum")
_should_skip(path) if endswith(path, ".min.js")
_should_skip(path) if endswith(path, ".min.css")
_should_skip(path) if endswith(path, ".min.html")
_should_skip(path) if endswith(path, ".min.json")

# Note: Pattern indicators are checked inline in rules using contains()
# CVSS base scores are mapped inline in rules

# Generate standardized finding
generate_finding(severity, level, rule_id, message, artifact_uri, start_line, snippet) = finding if {
  finding := {
    "rule_id": rule_id,
    "message": message,
    "artifact_uri": artifact_uri,
    "severity": severity,
    "level": level,
    "start_line": start_line,
    "snippet": snippet,
  }
}
# ── Comment awareness ────────────────────────────────────────────────────
# Line-oriented rules that gate on "the mitigation is not mentioned nearby"
# were suppressed by prose: a `// TODO: add ValidateAntiForgeryToken` comment
# silenced the finding it was describing. Rules must therefore test code, not
# comments, and must not reject a vulnerable line merely because it carries a
# trailing comment.

# is_comment_line reports whether the whole line is a comment, in any of the
# syntaxes the embedded corpus covers (C-family, hash, SQL, and the
# continuation lines of a block comment).
is_comment_line(line) if startswith(trim_space(line), "//")

is_comment_line(line) if startswith(trim_space(line), "/*")

is_comment_line(line) if startswith(trim_space(line), "*")

is_comment_line(line) if startswith(trim_space(line), "#")

is_comment_line(line) if startswith(trim_space(line), "--")

# code_window returns the text of lines [i-before, i+after] with whole-line
# comments removed, so a "not contains(window, <mitigation>)" guard cannot be
# defeated by a comment naming the mitigation.
code_window(lines, i, before, after) := txt if {
	start := max([0, i - before])
	end := min([count(lines) - 1, i + after])
	kept := [l | some j in numbers.range(start, end); l := lines[j]; not is_comment_line(l)]
	txt := concat("\n", kept)
}

# code_text returns the whole file with whole-line comments removed.
code_text(lines) := concat("\n", [l | some l in lines; not is_comment_line(l)])

# next_code_line returns the first non-blank, non-comment line strictly after
# index i and within `span` lines of it, along with its index. Rules that look
# at "the next line" were defeated by an intervening comment or blank line.
next_code_index(lines, i, span) := j if {
	end := min([count(lines) - 1, i + span])
	end >= i + 1
	candidates := [k |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		not is_comment_line(lines[k])
	]
	count(candidates) > 0
	j := candidates[0]
}

# ── One-hop taint linking ────────────────────────────────────────────────
# Many rules required the sink and the user-input source to sit on the SAME
# source line, so the ordinary two-line shape
#
#     String user = request.getParameter("u");
#     stmt.execute("... " + user);
#
# went undetected. tainted_var links them without a dataflow engine: an
# assignment from a source-matching expression within the preceding `before`
# lines, whose assigned identifier the sink line also references. Requiring the
# shared identifier is what keeps this from firing on any file that happens to
# read a request somewhere above.

# assigned_ident returns the identifier on the left of the first single `=` in
# a line, tolerating an optional `: Type` annotation (Rust, TypeScript, Kotlin).
assigned_ident(line) := v if {
	m := regex.find_all_string_submatch_n(`([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z0-9_:<>\[\], &]*)?=\s*[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# tainted_vars returns every variable assigned from `source_re` within the
# `before` lines above index i that line i also references. A set, not a single
# value: two tainted assignments above one sink is ordinary code, and a
# single-value function would abort the whole evaluation on the conflict.
tainted_vars(lines, i, before, source_re) := vs if {
	i > 0
	start := max([0, i - before])
	vs := {v |
		some j in numbers.range(start, i - 1)
		prev := lines[j]
		not is_comment_line(prev)
		regex.match(source_re, prev)
		v := assigned_ident(prev)
		regex.match(concat("", [`\b`, v, `\b`]), lines[i])
	}
}

# has_tainted_var is the boolean form, for rules that only need to know that
# the sink line consumes something a nearby line read from user input.
has_tainted_var(lines, i, before, source_re) if {
	count(tainted_vars(lines, i, before, source_re)) > 0
}

# reaches reports whether an identifier introduced at line j is consumed by
# line i — directly, or through one intermediate assignment. Two hops covers
# the shape a framework handler always takes:
#
#     public X download(@PathVariable String filename) {   // j
#         Path p = base.resolve(filename);                 // intermediate
#         return ok(new FileSystemResource(p));            // i
#
# Deeper chains need real dataflow and are deliberately out of scope here.
reaches(lines, j, i, ident) if {
	regex.match(concat("", [`\b`, ident, `\b`]), lines[i])
}

reaches(lines, j, i, ident) if {
	i - 1 >= j + 1
	some k in span(j + 1, i - 1)
	mid := lines[k]
	not is_comment_line(mid)
	regex.match(concat("", [`\b`, ident, `\b`]), mid)
	v := assigned_ident(mid)
	regex.match(concat("", [`\b`, v, `\b`]), lines[i])
}

# ── Test and fixture paths ───────────────────────────────────────────────
# Rules about hardening a running service (response headers, lock discipline,
# discarded errors, throwaway credentials) describe production behaviour. A
# test server, a mock and a fixture are not that surface, and reporting them
# buried the findings that were.

is_test_path(path) if endswith(path, "_test.go")

is_test_path(path) if regex.match(`(^|/)(testdata|tests?|__tests__|spec|specs|fixtures?|mocks?|e2e)/`, path)

is_test_path(path) if regex.match(`(^|/)test_[^/]*\.py$`, path)

is_test_path(path) if regex.match(`_test\.(py|rb|rs|c|cc|cpp)$`, path)

is_test_path(path) if regex.match(`\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs)$`, path)

is_test_path(path) if regex.match(`_spec\.rb$`, path)

is_test_path(path) if regex.match(`(Test|Tests|IT)\.java$`, path)

# ── Taint that survives multiple assignment ──────────────────────────────
# assigned_ident above takes the identifier left of the first `=`. For Go's
# `n, err := strconv.Atoi(s)` that is the blank or the error, never `n`.
# assigned_first takes the first name on the left, which is the value.

assigned_first(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:var\s+|let\s+|const\s+|final\s+|[A-Za-z_][\w<>\[\]\*\.]*\s+)?([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)*(?::=|=)[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
}

# tainted_names returns the variables assigned from `source_re` in the `before`
# lines above index i. Unlike tainted_vars it does not require the sink line to
# be checked here: callers test the specific argument they care about.
tainted_names(lines, i, before, source_re) := {v |
	i > 0
	some j in numbers.range(max([0, i - before]), i - 1)
	prev := lines[j]
	not is_comment_line(prev)
	regex.match(source_re, prev)
	v := assigned_first(prev)
}


# ── Index ranges ──────────────────────────────────────────────────────────
# numbers.range(a, b) counts DOWN when a > b: numbers.range(5, 4) is [5, 4],
# not []. The "lines strictly between two lines" idiom, range(i + 1, j - 1),
# therefore includes both neighbours when the lines are adjacent, and a guard
# that scans it matches the very lines that bound it. span is empty then.
span(a, b) := numbers.range(a, b) if a <= b

span(a, b) := [] if a > b

# ── Resolving a Java string that names an algorithm (or any setting) ────
#
# Production code seldom writes the algorithm at the call. It reads it from a
# configuration lookup with a default (props.getProperty("hash.alg", "SHA-1")),
# a Spring @Value placeholder, a constant on another class, or a ternary. The
# value that runs is the one the project's own configuration files give the
# key; the default only runs when no file defines it.

# Configuration files of the project (not test resources).
_cfg_props := {p |
	some p, _ in input.file_contents
	endswith(p, ".properties")
	not is_test_path(p)
}

_cfg_yaml := {p |
	some p, _ in input.file_contents
	regex.match(`\.ya?ml$`, p)
	not is_test_path(p)
}

_cfg_esc(key) := regex.replace(key, `[.\-\[\]()*+?^$|\\{}]`, `\$0`)

# Values a key takes across the project's .properties files, and for a dotted
# key the last segment in YAML files (application.yml nests the path).
config_values(key) := vals if {
	re := concat("", [`(?m)^[ \t]*`, _cfg_esc(key), `[ \t]*[=:][ \t]*([^\r\n#!]*)`])
	vals := {trim_space(m[1]) |
		some p in _cfg_props
		some m in regex.find_all_string_submatch_n(re, input.file_contents[p], -1)
	}
}

config_yaml_values(key) := vals if {
	seg := regex.replace(key, `^.*\.`, "")
	re := concat("", [`(?m)^[ \t]*`, _cfg_esc(seg), `[ \t]*:[ \t]*["']?([^\r\n#"']+)`])
	vals := {trim_space(m[1]) |
		some p in _cfg_yaml
		some m in regex.find_all_string_submatch_n(re, input.file_contents[p], -1)
	}
}

# The values a lookup of key can take: what the project's files define, else
# the default when the call gives one.
config_lookup(key, dflt, has_default) := vals if {
	d := config_values(key) | config_yaml_values(key)
	count(d) > 0
	vals := d
}

config_lookup(key, dflt, has_default) := {dflt} if {
	d := config_values(key) | config_yaml_values(key)
	count(d) == 0
	has_default
}

config_lookup(key, dflt, has_default) := set() if {
	d := config_values(key) | config_yaml_values(key)
	count(d) == 0
	not has_default
}

_java_lit := `"((?:[^"\\]|\\.)*)"`

# Every string a Java expression can evaluate to, when it is a literal, a
# ternary of literals or a properties lookup with an optional default.
java_rhs_values(rhs) := ((lits | terns) | props) | placeholders if {
	e := trim_space(rhs)
	lits := {m[1] | some m in regex.find_all_string_submatch_n(concat("", [`^`, _java_lit, `$`]), e, 1)}
	terns := {m[i] |
		some m in regex.find_all_string_submatch_n(concat("", [`^[^?"]*\?\s*`, _java_lit, `\s*:\s*`, _java_lit, `$`]), e, 1)
		some i in [1, 2]
	}
	props := {v |
		some m in regex.find_all_string_submatch_n(concat("", [`^(?:\(\s*String\s*\)\s*)?(?:[\w.]+\.)?(?:getProperty|getString|getOrDefault|getenv)\s*\(\s*`, _java_lit, `\s*(?:,\s*`, _java_lit, `\s*)?\)\s*(?:\.trim\(\))?$`]), e, 1)
		has := m[2] != ""
		some v in config_lookup(m[1], m[2], has)
	}
	placeholders := {v |
		some m in regex.find_all_string_submatch_n(`^"\$\{([\w.\-]+)(?::([^}"]*))?\}"$`, e, 1)
		some v in config_lookup(m[1], m[2], m[2] != "")
	}
}

# Names of locals and fields in this file that are assigned a value whose
# string is matched by weak (a full-string regex), plus Spring @Value fields
# whose placeholder resolves to one.
java_alg_vars(content, weak) := names if {
	a := {m[1] |
		some m in regex.find_all_string_submatch_n(`(?:^|[^=!<>\w.])(\w+)\s*=\s*([^;=][^;]*);`, content, -1)
		contains(m[2], "\"")
		some v in java_rhs_values(m[2])
		regex.match(weak, v)
	}
	b := {m[2] |
		some m in regex.find_all_string_submatch_n(`@Value\s*\(\s*("\$\{[^)]*\}")\s*\)\s*(?:(?:private|protected|public|final|static)\s+)*String\s+(\w+)`, content, -1)
		some v in java_rhs_values(m[1])
		regex.match(weak, v)
	}
	names := a | b
}

# Upper-case String constants (class or interface fields) in any Java file, so
# a call written getInstance(Settings.DIGEST) is resolved wherever DIGEST is.
java_global_consts(weak) := {m[1] |
	some p, c in input.file_contents
	endswith(p, ".java")
	contains(c, "String")
	not is_test_path(p)
	some m in regex.find_all_string_submatch_n(`\bString\s+([A-Z][A-Z0-9_]*)\s*=\s*([^;]+);`, c, -1)
	some v in java_rhs_values(m[2])
	regex.match(weak, v)
}

# The first argument of getInstance( when it is not a bare identifier: an
# inline lookup or ternary.
java_inline_alg(line, weak) if {
	some m in regex.find_all_string_submatch_n(`\bgetInstance\s*\(\s*((?:\(\s*String\s*\)\s*)?(?:[\w.]+\.)?(?:getProperty|getString|getOrDefault)\s*\([^()]*\)|[^,()"?]+\?\s*"[^"]*"\s*:\s*"[^"]*")\s*[,)]`, line, -1)
	some v in java_rhs_values(m[1])
	regex.match(weak, v)
}
