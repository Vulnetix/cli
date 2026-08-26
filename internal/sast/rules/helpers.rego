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
	some k in numbers.range(j + 1, i - 1)
	mid := lines[k]
	not is_comment_line(mid)
	regex.match(concat("", [`\b`, ident, `\b`]), mid)
	v := assigned_ident(mid)
	regex.match(concat("", [`\b`, v, `\b`]), lines[i])
}
