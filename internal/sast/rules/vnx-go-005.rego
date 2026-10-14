package vulnetix.rules.vnx_go_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-005",
	"name": "Go open redirect",
	"description": "A redirect sends the browser to a destination whose host the requester chooses: the URL given to http.Redirect, gin/echo c.Redirect(code, url), fiber c.Redirect(url) or a hand-written Location header starts with a value read from the request (r.URL.Query().Get, r.FormValue, r.PostFormValue, r.Form.Get, gin c.Query/DefaultQuery/PostForm/Param, echo c.QueryParam/FormValue, fiber c.Query/FormValue, gorilla/mux Vars, chi URLParam, r.PathValue), directly or through a variable assigned from it in the 25 lines above (including fmt.Sprintf(\"%s...\") and concatenation), or the value follows a prefix that does not pin the host (\"https://\" + v, \"//\" + v, or a bare \"/\" + v, which /evil.example turns into //evil.example). Not reported: a destination behind a fixed path or host (\"/items?id=\" + v, \"https://accounts.example.com/login?next=\" + url.QueryEscape(v)); a value checked in between (url.Parse, Host/IsAbs/Hostname tests, strings.HasPrefix, an allowlist, or a helper named for the check such as isLocalURL/safeRedirect/validateRedirect); a destination passed through a function call; constants, configuration values and the request's own r.URL.Path (canonical trailing-slash redirects); the call inside a string literal or comment.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-005/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [601],
	"capec": ["CAPEC-194"],
	"attack_technique": ["T1566"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["open-redirect", "web", "phishing"],
}

_request := `\b(?:r|req|request)\.(?:FormValue|PostFormValue)\(|\b(?:r|req|request)\.URL\.Query\(\)(?:\.Get\(|\[)|\b(?:r|req|request)\.(?:Form|PostForm)(?:\.Get\(|\[)|\bmux\.Vars\(|\.PathValue\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|GetQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

_sink_hint := `\.Redirect\(|"Location"`

_validator := `(?i)url\.Parse|\.Host\b|\.Hostname\(|\.IsAbs\(|\.Scheme\b|HasPrefix|allow|valid|safe|white_?list|trusted|is_?local|is_?relative|same_?origin|check_?redirect`

# Names assigned straight from a request read (optionally trimmed).
_direct := concat("", [`(?::=|=)\s*(?:strings\.\w+\(\s*)*(?:`, _request, `)`])

_word(v) := concat("", [`\b`, v, `\b`])

# A prefix that leaves the host to whatever follows it.
_open_prefix := `^(?:"(?:https?:)?//"|"/"|""|\x60(?:https?:)?//\x60)\s*\+\s*`

# A Sprintf whose format puts a value where the host is.
_open_format := `^fmt\.Sprintf\(\s*["\x60](?:(?:https?:)?//|/)?%[sv]`

# The expression starts with a request read or a tainted name.
_leads(e, _) if regex.match(concat("", [`^(?:`, _request, `)`]), e)

_leads(e, names) if {
	some v in names
	regex.match(concat("", [`^`, v, `\b`]), e)
	not regex.match(concat("", [`^`, v, `\s*\(`]), e)
}

# The destination expression starts with something the requester controls,
# directly, behind a prefix that does not pin the host, or as the first
# argument of a format that puts it where the host is.
_attacker_start(e, names) if _leads(e, names)

_attacker_start(e, names) if {
	regex.match(_open_prefix, e)
	_leads(regex.replace(e, _open_prefix, ""), names)
}

_attacker_start(e, names) if {
	regex.match(_open_format, e)
	args := regex.replace(e, `^fmt\.Sprintf\(\s*(?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60)\s*,\s*`, "")
	_leads(trim_space(args), names)
}

# Variables assigned straight from the request, then variables built from
# one of those so that the value still leads the string.
_names(lines, i) := t1 | t2 if {
	t1 := helpers.tainted_names(lines, i, 25, _direct)
	t2 := {v |
		count(t1) > 0
		some j in numbers.range(max([0, i - 25]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*:?=\s*(.+)$`, l, 1)
		count(m) > 0
		v := m[0][1]
		not v in t1
		_attacker_start(trim_space(m[0][2]), t1)
	}
}

# A line between the source and the sink that checks the variable.
_checked(lines, i, e, names) if {
	some v in names
	regex.match(concat("", [`^`, v, `\b`]), e)
	some k in numbers.range(max([0, i - 25]), i - 1)
	l := lines[k]
	regex.match(_word(v), l)
	not helpers.is_comment_line(l)
	regex.match(_validator, l)
}

# The call text: the line, plus its argument lines when the call is broken
# after '(' or ','.
_stmt(lines, i, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := s if {
	regex.match(`[(,]\s*$`, line)
	last := min([count(lines) - 1, i + 4])
	s := concat(" ", [trim_space(lines[k]) | some k in numbers.range(i, last)])
}

_first_arg(s) := trim_space(regex.replace(s, `^\s*((?:"(?:[^"\\]|\\.)*"|\x60[^\x60]*\x60|\((?:[^()"]|"(?:[^"\\]|\\.)*"|\([^()]*\))*\)|[^,()"\x60])*).*$`, "$1"))

_status := `^\s*(?:http\.Status\w+|\d{3}|code|status\w*)\s*,`

# The destination expression of each redirect form on the statement.
_dest(stmt) := e if {
	parts := regex.split(`\bhttp\.Redirect\(`, stmt)
	count(parts) > 1
	rest := regex.replace(parts[1], `^\s*[^,]+,\s*[^,]+,\s*`, "")
	e := _first_arg(rest)
}

# gin / echo: c.Redirect(code, url)
_dest(stmt) := e if {
	parts := regex.split(`\b(?:c|ctx|e|g)\.Redirect\(`, stmt)
	count(parts) > 1
	regex.match(_status, parts[1])
	e := _first_arg(regex.replace(parts[1], _status, ""))
}

# fiber: c.Redirect(url[, code])
_dest(stmt) := e if {
	parts := regex.split(`\b(?:c|ctx)\.Redirect\(`, stmt)
	count(parts) > 1
	not regex.match(_status, parts[1])
	e := _first_arg(parts[1])
}

_dest(stmt) := e if {
	parts := regex.split(`\.Header\(\)\.(?:Set|Add)\(\s*"Location"\s*,`, stmt)
	count(parts) > 1
	e := _first_arg(parts[1])
}

# The sink starts outside a string literal.
_in_code(line) if {
	m := regex.find_all_string_submatch_n(`^(.*?)(?:\.Redirect\(|\.Header\(\))`, line, 1)
	count(m) > 0
	prefix := regex.replace(m[0][1], `\\.`, "")
	not contains(prefix, "`")
	count(regex.find_all_string_submatch_n(`"`, prefix, -1)) % 2 == 0
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(_sink_hint, content)
	regex.match(_request, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_sink_hint, line)
	not helpers.is_comment_line(line)
	_in_code(line)
	e := _dest(_stmt(lines, i, line))
	names := _names(lines, i)
	_attacker_start(e, names)
	not _checked(lines, i, e, names)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect destination is taken from the request, so any host can be chosen (open redirect); accept only local paths (no scheme, no host, not starting with // or /\\) or hosts on an allowlist",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
