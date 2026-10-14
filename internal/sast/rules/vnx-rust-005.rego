package vulnetix.rules.vnx_rust_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-005",
	"name": "panic!() or unwrap()/expect() in function that returns Result",
	"description": "Reports panic!(...), .unwrap() and .expect(...) in the body of the function that directly encloses them when that function's signature (single- or multi-line, free function, method or main) returns Result: Result<T, E>, a crate alias such as Result<T>, io::Result, anyhow::Result or std::result::Result. The function already has an error channel, so a panic there aborts the thread where the error could have been propagated with ? or returned as Err, and the caller cannot recover. Not reported: functions returning anything else (including Option and fmt::Result, whose fmt::Error cannot carry the failure), a nested fn item that does not itself return Result, Mutex/RwLock lock().unwrap() and read()/write().expect() (the lock-poisoning convention), Regex::new or parse on a string literal (a programmer-controlled constant), #[cfg(test)] modules, #[test] functions, files under tests/, examples/ and benches/, build.rs, comments and string literals. unreachable!, todo! and assert! are not reported. VNX-RUST-002 separately reports unwrap on parsing runtime input anywhere.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-005/",
	"languages": ["rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [755],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["rust", "panic", "error-handling", "result"],
}

_unwrap := `\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\()`

_arg := `(?:[^()]*(?:\([^()]*(?:\([^()]*\)[^()]*)*\)[^()]*)*)`

# An explicit panic!, or unwrap/expect applied directly to an operation whose
# Result the function could have propagated with ?: file, network and process
# I/O, an awaited future, parsing, deserialising, decoding, database calls.
_panic_re := concat("", [
	`\bpanic!\s*[\(\{\[]|`,
	`(?:\b(?:File::open|File::create|OpenOptions::new\(\)[\w.()]*\.open|fs::\w+|read_to_string|read_to_end|read_exact|read_line|write_all|flush|sync_all|connect|bind|accept|send|recv|send_to|recv_from|spawn|output|status|wait|from_str|from_slice|from_reader|from_utf8|from_str_radix|from_value|parse|parse_str|decode|encode|serialize|deserialize|to_string_pretty|to_vec|query|query_row|query_one|execute|prepare|fetch_one|fetch_all|begin|commit|get_connection|canonicalize|metadata|remove_file|create_dir_all|set_permissions)\s*(?:::\s*<[^>]*>)?\s*\(`,
	_arg,
	`\)|\.await)`,
	_unwrap,
])

_fn_re := `^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+\w+`

# Segments that are deliberately not panics worth reporting: lock poisoning
# and unwrapping a constructor or parse of a string literal.
_benign_re := `\.\s*(?:lock|read|write|try_lock)\s*\(\s*\)\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\(\s*""\s*\))|::new\s*\(\s*(?:r#*)?""#*\s*\)\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\(\s*""\s*\))|""\s*\.\s*parse\s*(?:::\s*<[^>]*>)?\s*\(\s*\)\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\(\s*""\s*\))`

# The code part of a line: string literals emptied, trailing // comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# The statement text ending at line i (code only): the previous line joins
# when line i continues a method chain.
_text(lines, i) := concat(" ", [_code(lines[i - 1]), _code(lines[i])]) if {
	i > 0
	startswith(trim_space(lines[i]), ".")
}

_text(lines, i) := _code(lines[i]) if not startswith(trim_space(lines[i]), ".")

_text(lines, i) := _code(lines[i]) if {
	i == 0
	startswith(trim_space(lines[i]), ".")
}

_indent(line) :=count(line) - count(trim_left(line, " \t"))

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if regex.match(`(^|/)(examples|benches)/|(^|/)build\.rs$`, path)

# The line holding the `{` that opens the body of the fn declared at f.
_body_open(lines, f) := b if {
	cands := [k |
		some k in numbers.range(f, min([count(lines) - 1, f + 10]))
		regex.match(`\{\s*(?://.*)?$`, lines[k])
	]
	count(cands) > 0
	b := cands[0]
	not _decl_ends_before(lines, f, b)
}

# A trait method declaration (`fn x() -> T;`) has no body.
_decl_ends_before(lines, f, b) if {
	some k in numbers.range(f, b)
	regex.match(`;\s*$`, lines[k])
}

_encloses(lines, f, b, i) if {
	b < i
	not _closed(lines, b, i, _indent(lines[f]))
}

_closed(lines, a, z, ind) if {
	a + 1 <= z - 1
	some k in numbers.range(a + 1, z - 1)
	_indent(lines[k]) == ind
	startswith(trim_left(lines[k], " \t"), "}")
}

_enclosing_fn(lines, fns, i) := max(enc) if {
	enc := {f |
		some f in fns
		f < i
		i - f < 400
		b := _body_open(lines, f)
		_encloses(lines, f, b, i)
	}
	count(enc) > 0
}

_returns_result(lines, f) if {
	b := _body_open(lines, f)
	sig := concat(" ", array.slice(lines, f, b + 1))
	m := regex.find_all_string_submatch_n(`->\s*((?:[A-Za-z_]\w*::)*Result)\b`, sig, 1)
	count(m) > 0
	not endswith(m[0][1], "fmt::Result")
}

# Inside a #[cfg(test)] module or a #[test] function.
_in_test(lines, starts, i) if {
	some s in starts
	s < i
	nj := helpers.next_code_index(lines, s, 4)
	nj <= i
	regex.match(`\{\s*$`, lines[nj])
	not _closed(lines, nj, i, _indent(lines[s]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	not _skip_path(path)
	regex.match(`->\s*(?:[A-Za-z_]\w*::)*Result\b`, content)
	regex.match(`panic!|unwrap\s*\(\s*\)|expect\s*\(`, content)
	lines := split(content, "\n")
	cands := [i |
		some i, line in lines
		regex.match(`panic!|unwrap|expect`, line)
		not helpers.is_comment_line(line)
		regex.match(_panic_re, regex.replace(_text(lines, i), _benign_re, ""))
	]
	count(cands) > 0
	fns := [j | some j, l in lines; regex.match(_fn_re, l)]
	starts := [j | some j, l in lines; regex.match(`^\s*#\[(?:cfg\(test\)|test\]|tokio::test|rstest|test_case)`, l)]
	some i in cands
	line := lines[i]
	f := _enclosing_fn(lines, fns, i)
	_returns_result(lines, f)
	not _in_test(lines, starts, i)
	finding := {
		"rule_id": metadata.id,
		"message": "panic!()/unwrap()/expect() inside a function that returns Result aborts instead of reporting the error; use the ? operator or return Err(...) so the caller can handle it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
