package vulnetix.rules.vnx_cs_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-002",
	"name": "C# command injection: request data or a dynamic shell command reaches Process.Start",
	"description": "An operating-system command is started with text an attacker can influence. Reported: Process.Start(...), new ProcessStartInfo(...), a ProcessStartInfo FileName or Arguments assignment (on a ProcessStartInfo variable, on p.StartInfo, or inside a new ProcessStartInfo { ... } initializer) and PowerShell AddScript(...), when (a) the program or its arguments contain HTTP request data: Request.Query/QueryString/Form/Params/Cookies/Headers/RouteValues, Request[...], RouteData.Values or a WebForms TextBox .Text read inline or assigned up to 15 lines above (one further assignment is followed), a string or model parameter of a public action in a Controller/ControllerBase/PageModel class, a [FromQuery]/[FromRoute]/[FromForm]/[FromBody]/[FromHeader] parameter, or a minimal-API MapGet/MapPost lambda parameter; or (b) the program is a shell (cmd, cmd.exe, sh, bash, zsh, /bin/sh, powershell, pwsh) and the command string is built by concatenation with a non-constant operand, interpolation with a non-constant hole or string.Format, inline or in a variable assigned just above; or (c) AddScript receives script text built that way. Not reported: constant commands, ArgumentList.Add (no command-line parsing), dynamic arguments to a fixed non-shell program with no request data in sight (argument injection is possible but is not judged), numeric/Guid/bool action parameters, input checked first with Regex.IsMatch, TryParse or an allowlist Contains, FileName properties of other types (ContentDisposition, dialogs), and comments or log strings. Values passed in from another method are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-002/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "csharp"],
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# String contents are blanked before a sink is recognised.
_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# ── Statement text ───────────────────────────────────────────────────────

_ends_stmt(lines, j) if contains(lines[j], ";")

_ends_stmt(lines, j) if contains(lines[j], "{")

_ends_stmt(lines, j) if {
	j + 1 < count(lines)
	startswith(trim_space(lines[j + 1]), "{")
}

_stmt_end(lines, k) := e if {
	last := min([count(lines) - 1, k + 6])
	ends := [j | some j in numbers.range(k, last); _ends_stmt(lines, j)]
	e := min(array.concat([last], ends))
}

_stmt(lines, k) := concat(" ", array.slice(lines, k, _stmt_end(lines, k) + 1))

_after(stmt, re) := substring(stmt, indexof(stmt, m) + count(m), -1) if {
	m := regex.find_n(re, stmt, 1)[0]
}

# ── Request sources ──────────────────────────────────────────────────────

_src_re := `\b[Rr]equest\s*(\.\s*(QueryString|Query|Form|Params|Cookies|Headers|RouteValues|ServerVariables|Body|InputStream|RawUrl|PathInfo)\b|\[)|\bRouteData\.Values\b|\b(txt|tb)[A-Z]\w*\.Text\b|\bTextBox\w*\.Text\b`

_is_controller(content) if regex.match(`class\s+\w+[^{]*:\s*[\w.]*(Controller|ControllerBase|PageModel)\b|\[ApiController\]`, content)

# Parameter types that cannot carry a command.
_inert_type := `^(int|long|short|byte|sbyte|uint|ulong|ushort|bool|Guid|DateTime|DateTimeOffset|TimeSpan|decimal|double|float|CancellationToken|HttpContext|HttpRequest|IFormFile|object|EventArgs|\w+EventArgs)\??$`

_member_header(line) if regex.match(`^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|partial)\s+)+[\w<>\[\],.?\s]*?\b\w+\s*\(`, line)

_map_header(line) if regex.match(`\.Map(Get|Post|Put|Delete|Patch|Methods)?\s*\(`, line)

_param_names(text) := {p[2] |
	some raw in split(text, ",")
	p := regex.find_all_string_submatch_n(`^\s*(?:(?:ref|out|in|params|this)\s+)?([\w.]+(?:<[^>]*>)?(?:\[\])?\??)\s+([A-Za-z_]\w*)\s*(?:=.*)?$`, raw, 1)[0]
	not regex.match(_inert_type, p[1])
}

# The parameter list of the member header at h (attributes removed).
_header_params(lines, h) := plist if {
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	stripped := regex.replace(joined, `\[[^\]]*\]`, "")
	m := regex.find_all_string_submatch_n(`\w+\s*\(([^()]*)\)`, stripped, 1)
	count(m) > 0
	plist := m[0][1]
}

_bound_params(lines, h) := {p[2] |
	joined := concat(" ", array.slice(lines, h, min([count(lines), h + 5])))
	some p in regex.find_all_string_submatch_n(`\[From(?:Query|Route|Form|Body|Header)[^\]]*\]\s*([\w.<>\[\]?]+)\s+([A-Za-z_]\w*)`, joined, -1)
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
	ps := _param_names(_header_params(lines, h))
}

_bound_near(lines, i) := _bound_params(lines, _nearest_header(lines, i))

_map_params(lines, i) := ps if {
	hs := [k | some k in numbers.range(max([0, i - 15]), i); _map_header(lines[k])]
	count(hs) > 0
	ps := _lambda_params(lines, max(hs))
}

_params(lines, content, i) := {n | some n in _ctl_params(lines, content, i)} | {n | some n in _bound_near(lines, i)} | {n | some n in _map_params(lines, i)}

_direct(lines, content, i) := helpers.tainted_names(lines, i, 15, _src_re) | _params(lines, content, i)

_word(name, text) if regex.match(concat("", [`\b`, name, `\b`]), text)

# One more assignment: `var output = name + ".pdf"`.
_tainted(lines, content, i) := t0 | {v |
	some k in numbers.range(max([0, i - 15]), i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	some n in t0
	not regex.match(_start_re, l)
	_word(n, l)
	v := helpers.assigned_first(l)
} if {
	t0 := _direct(lines, content, i)
}

# A check between the source and the sink.
_guard_re := `(?i)\bRegex\.IsMatch\s*\(|\.IsMatch\s*\(|\bTryParse\s*\(|\b(allow|white|safe)\w*\.Contains\s*\(|\b(allow|white)list\b|\bIsValid\w*\s*\(`

_guarded(lines, i) if regex.match(_guard_re, helpers.code_window(lines, i, 15, 0))

_reaches_request(lines, content, i, arg) if regex.match(_src_re, arg)

_reaches_request(lines, content, i, arg) if {
	some n in _tainted(lines, content, i)
	_word(n, arg)
}

# ── Dynamic command text ─────────────────────────────────────────────────

_const_expr(e, _) if regex.match(`^(\w+\.)*[A-Z][A-Z0-9_]+$`, e)

_const_expr(e, consts) if e in consts

_const_expr(e, _) if regex.match(`^(nameof|typeof)\b|^\d`, e)

_const_expr(e, _) if e in {"Environment.NewLine", "string.Empty", "String.Empty"}

_dyn(t, _) if regex.match(`\b[Ss]tring\s*\.\s*(Format|Concat)\s*\(`, t)

_dyn(t, consts) if {
	regex.match(`\$+@?"|@\$+"`, t)
	some h in regex.find_all_string_submatch_n(`\{([^{}"]+)\}`, t, -1)
	e := trim_space(regex.replace(h[1], `[:,].*$`, ""))
	e != ""
	not regex.match(`^\d+$`, e)
	not _const_expr(e, consts)
}

_dyn(t, consts) if {
	some m in regex.find_all_string_submatch_n(`"\s*\+\s*\(?\s*([A-Za-z_][\w.]*)`, t, -1)
	not _const_expr(m[1], consts)
}

_dyn(t, consts) if {
	some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+\s*\$?@?"`, t, -1)
	not _const_expr(m[1], consts)
}

# Dynamic inline, or a variable assigned dynamic text a few lines above.
_dyn_arg(lines, i, arg, consts) if _dyn(arg, consts)

_dyn_arg(lines, i, arg, consts) if {
	some m in regex.find_all_string_submatch_n(`(?:^|,)\s*([A-Za-z_]\w*)\s*(?:[,);]|$)`, arg, -1)
	v := m[1]
	some k in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[k])
	regex.match(concat("", [`(^|[^\w.])`, v, `\s*\+?=\s*[^=]`]), lines[k])
	_dyn(_stmt(lines, k), consts)
}

_shell_lit := `@?"(?i:cmd|cmd\.exe|sh|bash|zsh|dash|/bin/(?:ba|z|da)?sh|/usr/bin/(?:ba|z)?sh|/usr/bin/env|powershell|powershell\.exe|pwsh|pwsh\.exe)"`

# ── Sinks ────────────────────────────────────────────────────────────────

_start_re := `\bProcess\s*\.\s*Start\s*\(|\bnew\s+(?:System\.Diagnostics\.)?ProcessStartInfo\s*\(`

# A ProcessStartInfo property: p.StartInfo.X, a ProcessStartInfo variable's
# X, or X inside a `new ProcessStartInfo { ... }` initializer.
_psi_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:System\.Diagnostics\.)?ProcessStartInfo\b`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\bProcessStartInfo\s+([A-Za-z_]\w*)\b`, content, -1)
}

_prop_re := `(?:^|[^\w.])(?:([A-Za-z_]\w*)\.)?(StartInfo\.)?(FileName|Arguments)\s*=\s*`

_in_psi_initializer(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i - 1)
	regex.match(`\bnew\s+(?:System\.Diagnostics\.)?ProcessStartInfo\b(?:\s*\(\s*\))?\s*(\{|$)`, lines[k])
	not _closed_between(lines, k, i)
}

_closed_between(lines, k, i) if {
	some j in numbers.range(k + 1, i - 1)
	regex.match(`^\s*\}`, lines[j])
}

_psi_prop(lines, code, psivars, i) := m[3] if {
	m := regex.find_all_string_submatch_n(_prop_re, code, 1)[0]
	m[2] != ""
}

_psi_prop(lines, code, psivars, i) := m[3] if {
	m := regex.find_all_string_submatch_n(_prop_re, code, 1)[0]
	m[2] == ""
	m[1] in psivars
}

_psi_prop(lines, code, psivars, i) := m[3] if {
	m := regex.find_all_string_submatch_n(_prop_re, code, 1)[0]
	m[2] == ""
	m[1] == ""
	regex.match(`^\s*(FileName|Arguments)\s*=`, code)
	_in_psi_initializer(lines, i)
}

# The process this Arguments value is for is a shell.
_shell_nearby(lines, i) if {
	w := helpers.code_window(lines, i, 8, 3)
	regex.match(concat("", [`(FileName\s*=\s*|ProcessStartInfo\s*\(\s*)`, _shell_lit]), w)
}

# (a) request data, anywhere in the call.
_req(lines, content, i, code, _) if {
	regex.match(_start_re, code)
	arg := _after(_stmt(lines, i), _start_re)
	_reaches_request(lines, content, i, arg)
	not _guarded(lines, i)
}

_req(lines, content, i, code, psivars) if {
	_psi_prop(lines, code, psivars, i)
	arg := _after(_stmt(lines, i), `(FileName|Arguments)\s*=\s*`)
	_reaches_request(lines, content, i, arg)
	not _guarded(lines, i)
}

_req(lines, content, i, code, _) if {
	regex.match(`\.AddScript\s*\(`, code)
	arg := _after(_stmt(lines, i), `\.AddScript\s*\(`)
	_reaches_request(lines, content, i, arg)
	not _guarded(lines, i)
}

# (b) a shell given a command built from data.
_shell(lines, i, code, _, consts) if {
	regex.match(_start_re, code)
	arg := _after(_stmt(lines, i), _start_re)
	regex.match(concat("", [`^\s*`, _shell_lit, `\s*,`]), arg)
	rest := regex.replace(arg, concat("", [`^\s*`, _shell_lit, `\s*,`]), "")
	_dyn_arg(lines, i, rest, consts)
}

_shell(lines, i, code, psivars, consts) if {
	_psi_prop(lines, code, psivars, i) == "Arguments"
	arg := _after(_stmt(lines, i), `Arguments\s*=\s*`)
	_dyn_arg(lines, i, arg, consts)
	_shell_nearby(lines, i)
}

# (c) PowerShell script text built from data.
_shell(lines, i, code, _, consts) if {
	regex.match(`\.AddScript\s*\(`, code)
	arg := _after(_stmt(lines, i), `\.AddScript\s*\(`)
	_dyn_arg(lines, i, arg, consts)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"Process", "AddScript"})
	lines := split(content, "\n")
	psivars := _psi_vars(content)
	consts := {m[1] |
		some l in lines
		contains(l, "const ")
		some m in regex.find_all_string_submatch_n(`\bconst\s+[\w.<>?]+\s+(\w+)\s*=`, l, -1)
	}
	some i, line in lines
	_has_any(line, {"Start", "FileName", "Arguments", "AddScript"})
	not helpers.is_comment_line(line)
	code := _code(line)
	kind := _kind(lines, content, i, code, psivars, consts)
	finding := {
		"rule_id": metadata.id,
		"message": _messages[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_kind(lines, content, i, code, psivars, _) := "request" if _req(lines, content, i, code, psivars)

_kind(lines, content, i, code, psivars, consts) := "shell" if {
	not _req(lines, content, i, code, psivars)
	_shell(lines, i, code, psivars, consts)
}

_messages := {
	"request": "HTTP request data reaches the program or arguments of a started process: an attacker chooses what runs. Map the input to a fixed allowlist of programs and pass each argument through ProcessStartInfo.ArgumentList, never through a shell",
	"shell": "A shell (cmd, sh, bash, PowerShell) is given a command line built from data: shell metacharacters in the value run extra commands. Run the target program directly and pass values through ProcessStartInfo.ArgumentList, or validate them against a strict allowlist",
}
