package vulnetix.rules.vnx_rust_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-002",
	"name": "Rust unwrap/expect on parsing or decoding runtime input",
	"description": "Reports .unwrap() or .expect(...) applied directly to the result of parsing, deserialising or decoding a runtime value: str::parse / parse::<T>(), serde_json/toml/serde_yaml from_str/from_slice/from_reader/from_value, String::from_utf8, from_str_radix, base64/hex decode, bincode::deserialize, postcard::from_bytes, Url::parse, Uuid::parse_str, IpAddr/SocketAddr/Version/NaiveDate parsing and Regex::new on a non-literal pattern, including the chain split across lines (.unwrap on the next line of a builder chain, or after the closing parenthesis of a call spread over several lines). Malformed input then panics the thread instead of returning an error, which an attacker who controls that input can use to crash a server or worker (CWE-248 uncaught exception; denial of service). Not reported: parsing a string literal, a raw string, include_str!/concat! or an ALL_CAPS constant (a programmer-controlled value), or a regex built from regex::escape(...); procedural-macro files (use proc_macro / #[proc_macro...]), where a panic is a compile error on the macro input; ?, unwrap_or, unwrap_or_default, unwrap_or_else and match; .unwrap() on other operations (Mutex::lock, Option::first, File::open, env::var), which are left to review because most are invariants rather than input handling; #[cfg(test)] modules, #[test] functions, files under tests/, examples/ and benches/, build.rs; comments and string literals. VNX-RUST-005 separately reports panics in Result-returning functions.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-002/",
	"languages": ["rust"],
	"severity": "low",
	"level": "warning",
	"kind": "sast",
	"cwe": [248],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["error-handling", "panic", "robustness"],
}

_unwrap := `\s*\.\s*(?:unwrap\s*\(\s*\)|expect\s*\()`

_arg := `([^()]*(?:\([^()]*\)[^()]*)*)`

# receiver.parse() / parse::<T>() immediately unwrapped; group 1 is the
# character before the dot, so a string-literal receiver can be told apart.
_parse_re := concat("", [`(\w+|.)\s*\.parse\s*(?:::\s*<[^>]*>)?\s*\(\s*\)`, _unwrap])

# A decoding call immediately unwrapped; group 1 is its argument list.
_call_re := concat("", [
	`(?:\b(?:from_str|from_slice|from_reader|from_bytes|from_utf8|from_str_radix|from_value|deserialize|parse_str|decode|decode_config|parse_from_rfc3339|parse_from_str)|\b(?:Url|Uri|Uuid|Regex|RegexBuilder|IpAddr|Ipv4Addr|Ipv6Addr|SocketAddr|Version|VersionReq|NaiveDate|NaiveDateTime|Mime|HeaderValue)::(?:parse|new|from_str))\s*(?:::\s*<[^>]*>)?\s*\(`,
	_arg, `\)`, _unwrap,
])

_literal_arg_re := `^\s*&?\s*(?:"|r#*"|b"|br#*"|include_str!|include_bytes!|concat!|env!|[A-Z][A-Z0-9_]*\s*(?:,|$)|[A-Z][A-Z0-9_]*\.as_)`

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if regex.match(`(^|/)(examples|benches)/|(^|/)build\.rs$|(^|/)test_?utils?\.rs$`, path)

# The comment block directly above the statement explains why the value
# cannot be malformed ("We just verified that the range is ASCII ...").
_justified(lines, i) if {
	s := _stmt_start(lines, i)
	s > 0
	some j in numbers.range(max([0, s - 6]), s - 1)
	helpers.is_comment_line(lines[j])
	regex.match(`(?i)verified|validated|already checked|guarantee|always valid|cannot fail|can't fail|never fail|infallible|invariant`, lines[j])
	not _code_between(lines, j, s)
}

_stmt_start(lines, i) := i - 1 if {
	i > 0
	startswith(trim_space(lines[i]), ".")
}

_stmt_start(lines, i) := i if not startswith(trim_space(lines[i]), ".")

_stmt_start(lines, i) := i if {
	i == 0
	startswith(trim_space(lines[i]), ".")
}

_code_between(lines, j, s) if {
	j + 1 <= s - 1
	some k in numbers.range(j + 1, s - 1)
	not helpers.is_comment_line(lines[k])
}

# The statement text ending at line i: when line i continues a method chain or
# closes a call opened above (it starts with "." or ")"), up to three previous
# lines join, and only a match whose unwrap is on line i counts (the tail
# anchor), so an unwrap on an earlier line is never reported twice.
_continues(line) if regex.match(`^\s*[.)]`, line)

_text(lines, i) := concat("\n", array.slice(lines, max([0, i - 3]), i + 1)) if {
	i > 0
	_continues(lines[i])
}

_text(lines, i) := lines[i] if not _continues(lines[i])

_text(lines, i) := lines[i] if {
	i == 0
	_continues(lines[i])
}

_tail(lines, i) := `[^\n]*$` if {
	i > 0
	_continues(lines[i])
}

_tail(lines, i) := "" if not _continues(lines[i])

_tail(lines, i) := "" if {
	i == 0
	_continues(lines[i])
}

_reported(text, tail) if {
	some m in regex.find_all_string_submatch_n(concat("", [_parse_re, tail]), text, -1)
	m[1] != "\""
	m[1] != "#"
	not regex.match(`^[A-Z][A-Z0-9_]*$`, m[1])
}

_reported(text, tail) if {
	some m in regex.find_all_string_submatch_n(concat("", [_call_re, tail]), text, -1)
	not regex.match(_literal_arg_re, m[1])
	not regex.match(`(?i)escape`, m[1])
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# Inside a #[cfg(test)] module or a #[test] function.
_in_test(lines, starts, i) if {
	some s in starts
	s < i
	nj := helpers.next_code_index(lines, s, 4)
	nj <= i
	regex.match(`\{\s*$`, lines[nj])
	not _closed(lines, nj, i, _indent(lines[s]))
}

_closed(lines, a, b, ind) if {
	a + 1 <= b - 1
	some k in numbers.range(a + 1, b - 1)
	_indent(lines[k]) == ind
	startswith(trim_left(lines[k], " \t"), "}")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	not _skip_path(path)
	regex.match(`(?:unwrap\s*\(\s*\)|expect\s*\()`, content)
	regex.match(`parse|from_|decode|deserialize|::new`, content)
	# A procedural macro runs inside the compiler: a panic there is a compile
	# error on the macro's own input, not a crash on runtime data.
	not regex.match(`(?m)^\s*(?:use proc_macro|#\[proc_macro)`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.\s*(?:unwrap\s*\(\s*\)|expect\s*\()`, line)
	not helpers.is_comment_line(line)
	text := regex.replace(regex.replace(_text(lines, i), `"(?:[^"\\\n]|\\.)*"`, `""`), `//[^\n]*$`, "")
	_reported(text, _tail(lines, i))
	starts := [j | some j, l in lines; regex.match(`^\s*#\[(?:cfg\(test\)|test\]|tokio::test|rstest|test_case)`, l)]
	not _in_test(lines, starts, i)
	not _justified(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Parsing or decoding a runtime value is unwrapped; malformed input panics instead of returning an error. Propagate it with ? or handle the Err/None case (match, unwrap_or, ok_or)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
