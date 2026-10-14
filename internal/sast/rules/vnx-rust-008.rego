package vulnetix.rules.vnx_rust_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-008",
	"name": "Rust path traversal in Actix-web or Axum file-serving handler",
	"description": "A value taken from an axum or actix-web request (a Path(name) / Path((a, b)) / Query(q) / Json / Form extractor, a web::Path<...> / web::Query<...> parameter, or HttpRequest::match_info()), directly or through one let binding such as path.into_inner() or format!(...), reaches a filesystem path or file operation in the same handler: .join(...), Path::new, PathBuf::from, File::open/create, std::fs or tokio::fs read/write/remove/copy/rename, NamedFile::open, ServeFile::new or OpenOptions. A request value containing ../ or an absolute path then reads or writes files outside the intended directory. Not reported: handlers that canonicalize the path and check starts_with against the base, reject \"..\" (contains(\"..\")), keep only file_name(), check Component::ParentDir / Component::Normal, or call a sanitize/safe_join helper; extractors of integer, bool or Uuid type; paths built from configuration rather than the request; comments and string literals. Flows through more than one intermediate binding or across functions are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-008/",
	"languages": ["rust"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "rust", "actix", "axum"],
}

_sink_re := `\.join\s*\(|\bPath::new\s*\(|\bPathBuf::from\s*\(|\bFile::(?:open|create)\s*\(|\bfs::(?:read|read_to_string|read_dir|write|remove_file|remove_dir_all|create_dir_all|copy|rename|File)\b|\bNamedFile::open\b|\bServeFile::new\b|\bOpenOptions\b`

_guard_re := `canonicalize[\s\S]*starts_with|starts_with[\s\S]*canonicalize|contains\s*\(\s*"\.\.|contains\s*\(\s*'\.'|ParentDir|Component::Normal|\.file_name\s*\(\s*\)|(?i)sanitiz|safe_join|secure_join|is_safe_path`

_safe_type_re := `^\s*(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool|Uuid|uuid::Uuid)\s*$`

# The code part of a line: string literals emptied, trailing // comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

_fn_start(lines, i) := max(array.concat([max([0, i - 40])], [j |
	some j in numbers.range(max([0, i - 40]), i)
	regex.match(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+`, lines[j])
]))

_fn_end(lines, i) := min(array.concat([min([count(lines) - 1, i + 8])], [j |
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	regex.match(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+`, lines[j])
]))

# Extractor and request names declared between fs and i.
_base_names(lines, fs, i) := {v |
	some j in numbers.range(fs, i)
	not helpers.is_comment_line(lines[j])
	some v in _line_names(lines[j])
}

_line_names(line) := {v |
	some m in regex.find_all_string_submatch_n(`\b(?:Path|Query|Json|Form)\s*\(\s*([a-z_]\w*)\s*\)(?:\s*:\s*\w+\s*<([^>]*)>)?`, line, -1)
	not regex.match(_safe_type_re, m[2])
	v := m[1]
} | {v |
	some m in regex.find_all_string_submatch_n(`\bPath\s*\(\s*\(([^)]*)\)\s*\)`, line, -1)
	some part in split(m[1], ",")
	v := trim_space(part)
	regex.match(`^[a-z_]\w*$`, v)
} | {v |
	some m in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\s*:\s*(?:actix_web::)?(?:web::)?(?:Path|Query|Json|Form)\s*<([^>]*)>`, line, -1)
	not regex.match(_safe_type_re, m[2])
	v := m[1]
} | {v |
	some m in regex.find_all_string_submatch_n(`\b([a-z_]\w*)\s*:\s*&?\s*(?:actix_web::)?HttpRequest\b`, line, -1)
	v := m[1]
}

_refs(line, v) if regex.match(concat("", [`(?:^|[^.\w])`, v, `\b`]), line)

_let_name(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*let\s+(?:mut\s+)?([a-z_]\w*)\s*(?::[^=]*)?=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

# One hop: a let binding (that is not itself a sink) computed from a request name.
_tainted(lines, fs, i) := names if {
	base := _base_names(lines, fs, i)
	derived := {v |
		some j in numbers.range(fs, i - 1)
		j < i
		code := _code(lines[j])
		not helpers.is_comment_line(lines[j])
		not regex.match(_sink_re, code)
		some b in base
		_refs(code, b)
		v := _let_name(code)
	}
	names := base | derived
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	regex.match(`\b(?:Path|Query|Json|Form)\s*[<(]|HttpRequest`, content)
	regex.match(_sink_re, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code(line)
	regex.match(_sink_re, code)
	fs := _fn_start(lines, i)
	some v in _tainted(lines, fs, i)
	_refs(code, v)
	not _is_declaration(code, v)
	not regex.match(_guard_re, helpers.code_window(lines, i, i - fs, _fn_end(lines, i) - i))
	finding := {
		"rule_id": metadata.id,
		"message": "A request-supplied path component reaches a filesystem path without validation; '../' or an absolute path escapes the base directory. Canonicalize the joined path and require it starts_with the canonical base, or reject anything but a single Component::Normal",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The handler signature itself (Path(name): Path<String>) is not a use.
_is_declaration(code, v) if v in _line_names(code)
