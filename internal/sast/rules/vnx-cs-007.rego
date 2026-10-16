package vulnetix.rules.vnx_cs_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-007",
	"name": "C# path traversal: request data reaches Path.Combine, MapPath or a file-system API",
	"description": "A file-system path is built from data an HTTP client controls, so ../ sequences or an absolute path read, write or delete files outside the intended directory. Reported: Path.Combine/Path.Join and MapPath (any argument), File.Copy/Move/Replace (either path), and the path argument of File.Read*/Write*/Append*/Open*/Create/Delete, Directory.Delete/CreateDirectory/GetFiles/Enumerate*, new FileStream/StreamReader/StreamWriter/FileInfo/DirectoryInfo, PhysicalFile, new PhysicalFileResult, Results.File and Response.TransmitFile/WriteFile/SaveAs, when that argument contains request data: Request.Query/QueryString/Form/Params/Cookies/Headers/RouteValues/Path, Request[...], RouteData.Values, a WebForms TextBox .Text, an uploaded file's FileName (also the loop variable of foreach over Request.Form.Files), an archive entry's FullName or Key (zip slip), a string parameter of a controller action, a [FromQuery]/[FromRoute]/[FromForm] parameter or a minimal-API lambda parameter, inline or through a variable assigned up to 15 lines above (one further assignment is followed). A flow is reported once, at the first sink. Not reported: values passed through Path.GetFileName, a resolved path checked with GetFullPath and StartsWith, values checked by Regex.IsMatch, an allowlist or an IsValid method, Guid/int and other non-string parameters, request data written as file content rather than used as the path, constant paths, parameters of non-controller methods (the caller is not followed), and the pattern in comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-007/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "csharp"],
}

# ── Text helpers ─────────────────────────────────────────────────────────

# Plain (non-interpolated) string literals are emptied; interpolated ones
# keep their holes.
_code(line) := regex.replace(line, `(^|[^$@"])"(?:\\.|[^"\\])*"`, `$1""`)

_ends_stmt(lines, j) if contains(lines[j], ";")

_ends_stmt(lines, j) if contains(lines[j], "{")

_stmt_end(lines, k) := e if {
	last := min([count(lines) - 1, k + 6])
	ends := [j | some j in numbers.range(k, last); _ends_stmt(lines, j)]
	e := min(array.concat([last], ends))
}

_stmt(lines, k) := _code(concat(" ", array.slice(lines, k, _stmt_end(lines, k) + 1)))

_word(name, text) if regex.match(concat("", [`\b`, name, `\b`]), text)

# Everything up to the parenthesis that closes the call (three levels).
_span_re := `^(?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*`

_first_re := `^(?:[^(),]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*`

# A path segment run through Path.GetFileName can no longer leave the directory.
_strip_safe(t) := regex.replace(t, `\bPath\s*\.\s*GetFileName(?:WithoutExtension)?\s*\((?:[^()]|\([^()]*\))*\)`, "")

# ── Sinks ────────────────────────────────────────────────────────────────

_all_args_re := `\bPath\s*\.\s*(?:Combine|Join)\s*\(|\bMapPath\s*\(|\b(?:File|Directory)\s*\.\s*(?:Copy|Move|Replace)\s*\(`

_first_arg_re := `\bFile\s*\.\s*(?:ReadAllText|ReadAllBytes|ReadAllLines|ReadLines|ReadAllTextAsync|ReadAllBytesAsync|ReadAllLinesAsync|OpenRead|OpenText|OpenWrite|Open|Create|CreateText|Delete|WriteAllText|WriteAllBytes|WriteAllLines|WriteAllTextAsync|WriteAllBytesAsync|WriteAllLinesAsync|AppendAllText|AppendAllLines|AppendText|AppendAllTextAsync)\s*\(|\bDirectory\s*\.\s*(?:Delete|CreateDirectory|GetFiles|GetDirectories|EnumerateFiles|EnumerateDirectories|GetFileSystemEntries)\s*\(|\bnew\s+(?:System\.IO\.)?(?:FileStream|StreamReader|StreamWriter|FileInfo|DirectoryInfo)\s*\(|(?:^|[^\w.])PhysicalFile\s*\(|\bnew\s+(?:[\w.]*\.)?PhysicalFileResult\s*\(|\bResults\s*\.\s*File\s*\(|\.\s*(?:TransmitFile|WriteFile|SaveAs)\s*\(`

_sink_re := concat("|", [_all_args_re, _first_arg_re])

_ms_at(ms, j) := ms[j] if j < count(ms)

_ms_at(ms, j) := "" if j >= count(ms)

# The argument text each sink call on the statement receives.
_sink_args(stmt) := {a |
	ms := regex.find_n(_sink_re, stmt, -1)
	pieces := regex.split(_sink_re, stmt)
	some k, m in ms
	rest := concat("", [concat("", [pieces[j], _ms_at(ms, j)]) |
		some j in helpers.span(k + 1, count(pieces) - 1)
	])
	span := regex.find_n(_span_re, rest, 1)[0]
	a := _call_arg(m, span)
}

_call_arg(m, span) := span if regex.match(concat("", [`^(?:`, _all_args_re, `)$`]), m)

_call_arg(m, span) := regex.find_n(_first_re, span, 1)[0] if {
	not regex.match(concat("", [`^(?:`, _all_args_re, `)$`]), m)
}

# ── Sources ──────────────────────────────────────────────────────────────

_src_re := `\b[Rr]equest\s*(\.\s*(QueryString|Query|Form|Params|Cookies|Headers|RouteValues|ServerVariables|Path|PathInfo|RawUrl|Files)\b|\[)|\bRouteData\.Values\b|\b(txt|tb)[A-Z]\w*\.Text\b|\bTextBox\w*\.Text\b|(?i:\b\w*(?:file|upload|posted|attachment)\w*)\.FileName\b|(?i:\b\w*entry)\.(?:FullName|Key)\b`

_is_controller(content) if regex.match(`class\s+\w+[^{]*:\s*[\w.]*(Controller|ControllerBase|PageModel)\b|\[ApiController\]`, content)

_inert_type := `^(int|long|short|byte|sbyte|uint|ulong|ushort|bool|Guid|DateTime|DateTimeOffset|TimeSpan|decimal|double|float|CancellationToken|HttpContext|HttpRequest|HttpResponse|IFormCollection|object|EventArgs|\w+EventArgs|int\[\]|long\[\])\??$`

_member_header(line) if regex.match(`^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial)\s+)+[\w<>\[\],.?\s]*?\b\w+\s*\(`, line)

# A constructor: modifiers then the class name, no return type. Its parameters
# are injected services, not request data.
_ctor_header(line) if regex.match(`^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static)\s+)+\w+\s*\(`, line)

_map_header(line) if regex.match(`\.Map(Get|Post|Put|Delete|Patch|Methods)?\s*\(`, line)

_param_names(text) := {p[2] |
	some raw in split(text, ",")
	p := regex.find_all_string_submatch_n(`^\s*(?:(?:ref|out|in|params|this)\s+)?([\w.]+(?:<[^>]*>)?(?:\[\])?\??)\s+([A-Za-z_]\w*)\s*(?:=.*)?$`, raw, 1)[0]
	not regex.match(_inert_type, p[1])
}

_header_params(lines, h) := plist if {
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	stripped := regex.replace(joined, `\[[^\]]*\]`, "")
	m := regex.find_all_string_submatch_n(`\w+\s*\(([^()]*)\)`, stripped, 1)
	count(m) > 0
	plist := m[0][1]
}

_bound_params(lines, h) := {p[2] |
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	some p in regex.find_all_string_submatch_n(`\[From(?:Query|Route|Form|Header)[^\]]*\]\s*([\w.<>\[\]?]+)\s+([A-Za-z_]\w*)`, joined, -1)
	not regex.match(_inert_type, p[1])
}

_lambda_params(lines, h) := {n |
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 3])))
	stripped := regex.replace(joined, `\[[^\]]*\]`, "")
	some m in regex.find_all_string_submatch_n(`\(([^()]*)\)\s*=>`, stripped, -1)
	some n in _param_names(m[1])
}

_nearest_header(lines, i) := h if {
	hs := [k | some k in numbers.range(max([0, i - 60]), i); _member_header(lines[k])]
	count(hs) > 0
	h := max(hs)
}

_ctl_params(lines, content, i) := ps if {
	_is_controller(content)
	h := _nearest_header(lines, i)
	regex.match(`^\s*(?:\[[^\]]*\]\s*)*public\b`, lines[h])
	not _ctor_header(lines[h])
	ps := _param_names(_header_params(lines, h))
}

_bound_near(lines, i) := _bound_params(lines, _nearest_header(lines, i))

_map_params(lines, i) := ps if {
	hs := [k | some k in numbers.range(max([0, i - 15]), i); _map_header(lines[k])]
	count(hs) > 0
	ps := _lambda_params(lines, max(hs))
}

_params(lines, content, i) := {n | some n in _ctl_params(lines, content, i)} | {n | some n in _bound_near(lines, i)} | {n | some n in _map_params(lines, i)}

# A line that assigns a value that can carry a path (not stripped by
# GetFileName and not itself a sink, so a flow is reported once).
_carrier(l) if {
	not helpers.is_comment_line(l)
	not contains(l, "GetFileName")
	not regex.match(_sink_re, _code(l))
}

_direct(lines, content, i) := {v |
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	regex.match(_src_re, _code(l))
	_carrier(l)
	v := helpers.assigned_first(l)
} | {m[1] |
	# foreach (var file in Request.Form.Files): the loop variable.
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	contains(l, "foreach")
	not helpers.is_comment_line(l)
	some m in regex.find_all_string_submatch_n(`\bforeach\s*\(\s*[\w.<>?]+\s+([A-Za-z_]\w*)\s+in\s+(.*)\)`, _code(l), 1)
	regex.match(_src_re, m[2])
} | _params(lines, content, i)

_tainted(lines, content, i) := t0 | {v |
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	_carrier(l)
	some n in t0
	_word(n, _code(l))
	v := helpers.assigned_first(l)
	not v in t0
} if {
	t0 := _direct(lines, content, i)
}

_reaches(_, _, _, arg) if regex.match(_src_re, arg)

_reaches(lines, content, i, arg) if {
	some n in _tainted(lines, content, i)
	_word(n, arg)
}

# ── Guards ───────────────────────────────────────────────────────────────

_guard_re := `(?i)\bRegex\.IsMatch\s*\(|\.IsMatch\s*\(|\b(allow|white|safe|permit)\w*\.Contains\s*\(|\bIsValid\w*\s*\(|\.Contains\s*\(\s*"\.\."|\.IndexOf\s*\(\s*"\.\."|GetInvalid(?:FileName|Path)Chars`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 15, 0))

_guarded(lines, i) if {
	w := helpers.code_window(lines, i, 15, 4)
	contains(w, "GetFullPath")
	regex.match(`\.StartsWith\s*\(`, w)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	regex.match(concat("", [`(?m)`, _sink_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _code(line))
	stmt := _stmt(lines, i)
	some arg in _sink_args(stmt)
	_reaches(lines, content, i, _strip_safe(arg))
	not _guarded(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "HTTP request data becomes part of a file-system path: ../ sequences or an absolute path escape the intended directory. Strip directories with Path.GetFileName, or resolve the path with Path.GetFullPath and verify it starts with the base directory before using it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
