package vulnetix.rules.vnx_py_020

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-020",
	"name": "tarfile.extractall() without path validation (zip slip)",
	"description": "A tar archive is extracted with no extraction filter and no member validation, in a .py file. Reported: extractall() or extract() on a TarFile (a name bound by `x = tarfile.open(...)`, `tarfile.TarFile(...)`/`TarFile.open(...)` or `with tarfile.open(...) as x`, a parameter annotated TarFile, module aliases and a from-imported TarFile included) and tarfile.open(...).extractall(...) chained, when the call passes no filter= (or filter='fully_trusted'/fully_trusted_filter/None) and no members= other than x.getmembers(), arguments read across a call broken over lines. A member named ../../etc/cron.d/x, an absolute path or a symlink then writes outside the destination (CVE-2007-4559, CWE-22). Use filter='data' (Python 3.12+, the default from 3.14), tarfile.data_filter, or validate each member's resolved path. Not reported: a call with filter='data'/'tar'/data_filter, members= from a filtering function, extraction preceded within 15 lines by a getmembers()/member loop that checks paths (realpath, abspath, commonpath, is_relative_to, startswith, '..', isabs, issym/islnk), a file that sets TarFile.extraction_filter, zipfile extraction (zipfile sanitises member names), extractfile(), and the calls in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-020/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "zip-slip", "tarfile", "python"],
}

_code(line) := regex.replace(
	regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`),
	`#.*$`, "",
)

_modules(content) := {"tarfile"} | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+tarfile\s+as\s+(\w+)`, content, -1)
}

# A regex for a TarFile constructor call in this file.
_ctor_re(content) := concat("", [`(?:\b(?:`, concat("|", _modules(content)), `)\.(?:open|TarFile(?:\.open)?)`, _bare_tarfile(content), `)\s*\(`])

_bare_tarfile(content) := `|(?:^|[^\w.])TarFile(?:\.open)?` if {
	regex.match(`(?m)^\s*from\s+tarfile\s+import\s[^\n]*\bTarFile\b`, content)
}

_bare_tarfile(content) := "" if {
	not regex.match(`(?m)^\s*from\s+tarfile\s+import\s[^\n]*\bTarFile\b`, content)
}

# Names bound to a TarFile.
_tar_names(code, ctor) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*(\w+)\s*=\s*`, ctor]), code, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)\bwith\s*`, ctor, `[^\n]*?\)\s+as\s+(\w+)`]), code, -1)
} | {m[1] |
	# a parameter annotated as a TarFile: def unpack(tar: tarfile.TarFile, ...)
	some m in regex.find_all_string_submatch_n(`(\w+)\s*:\s*(?:\w+\.)?TarFile\b`, code, -1)
}

# The call's arguments: the rest of the line, or the following lines up to the
# one that closes the call.
# Raw text (string values kept) so filter="data" can be read.
_args(_, line, _, rest) := line if contains(rest, ")")

_args(lines, line, i, rest) := concat(" ", array.concat([line], [lines[k] | some k in numbers.range(i + 1, e); not helpers.is_comment_line(lines[k])])) if {
	not contains(rest, ")")
	end := min([count(lines) - 1, i + 6])
	closes := [k | some k in numbers.range(i + 1, end); contains(_code(lines[k]), ")")]
	e := _first_or(closes, end)
}

_first_or(xs, _) := xs[0] if count(xs) > 0

_first_or(xs, d) := d if count(xs) == 0

_unsafe_filter(args) if regex.match(`\bfilter\s*=\s*(?:None\b|""|''|["']fully_trusted["']|[\w.]*fully_trusted)`, args)

_safe(args) if {
	regex.match(`\bfilter\s*=`, args)
	not _unsafe_filter(args)
}

_safe(args) if {
	m := regex.find_all_string_submatch_n(`\bmembers\s*=\s*([\w.]+(?:\([^()]*\))?)`, args, 1)
	count(m) > 0
	not regex.match(`^\s*\w+\.getmembers\(\)\s*$`, m[0][1])
}

# A member loop that checks paths in the lines above.
_guarded(lines, i) if {
	w := helpers.code_window(lines, i - 1, 15, 0)
	regex.match(`getmembers\(\)|\bfor\s+\w+\s+in\s+\w+\s*:`, w)
	regex.match(`realpath|abspath|commonpath|commonprefix|is_relative_to|\.startswith\(|["']\.\.["']|isabs\(|\.issym\(|\.islnk\(|\.resolve\(`, w)
}

_global_filter(content) if {
	regex.match(`(?m)^[^#\n]*\bextraction_filter\s*=`, content)
	not regex.match(`(?m)^[^#\n]*\bextraction_filter\s*=\s*[^\n]*fully_trusted`, content)
}

_sink(code, names, ctor) := [m[0][1], m[0][2]] if {
	some n in names
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.])`, n, `\.(extractall|extract)\s*\((.*)$`]), code, 1)
	count(m) > 0
}

_sink(code, _, ctor) := [m[0][1], m[0][2]] if {
	m := regex.find_all_string_submatch_n(concat("", [ctor, `.*\)\.(extractall|extract)\s*\((.*)$`]), code, 1)
	count(m) > 0
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "tarfile")
	contains(content, ".extract")
	not _global_filter(content)
	ctor := _ctor_re(content)
	lines := split(content, "\n")
	names := _tar_names(concat("\n", [_code(l) | some l in lines]), ctor)
	some i, line in lines
	contains(line, ".extract")
	not helpers.is_comment_line(line)
	code := _code(line)
	s := _sink(code, names, ctor)
	args := _args(lines, line, i, s[1])
	not _safe(args)
	_reportable(args, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("tarfile %v() without filter='data' or member path validation lets an archive entry write outside the destination (zip slip); pass filter='data' or validate each member", [s[0]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# An explicit fully_trusted filter is reported even after a member check.
_reportable(args, _, _) if _unsafe_filter(args)

_reportable(args, lines, i) if {
	not _unsafe_filter(args)
	not _guarded(lines, i)
}
