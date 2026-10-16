# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_606

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-606",
	"name": "Unchecked Input for Loop Condition",
	"description": "Reports a loop whose bound is a number parsed from untrusted input with no upper limit checked first, so a caller chooses how long the loop runs (CPU exhaustion). The loop is a C/C++/Java/Go `for (...; i < N; ...)`, `while (i < N)`, a count-down `while (N-- > 0)` / `while (N--)` / `for (; N > 0; N--)`, or Go `for i := range N`, and N is, within the 25 lines above: assigned from atoi/atol/strtol/strtoul/ntohl/ntohs over argv, getenv or optarg, or read with scanf(\"%u\", &N) (C/C++); assigned from Integer.parseInt/valueOf, Long.parseLong or Scanner.nextInt over request.getParameter/getHeader or a variable read from one, or a @RequestParam/@PathVariable/@QueryParam int parameter, annotation arguments included (Java); assigned from strconv.Atoi/ParseInt/ParseUint over r.URL.Query(), FormValue, Header.Get, gin c.Query/c.Param, mux.Vars or os.Args, directly or through one variable (Go). Not reported: a bound compared against a limit in an if between the parse and the loop, a bound clamped with min()/Math.min or reassigned from a clamp/limit/bound helper, a bound passed to a verify/validate/check function, a loop in a different function from the parse (a function or method declaration between them), count-down loops over values decoded with ntohs/ntohl (protocol code validates message lengths elsewhere), a loop header that also tests a second condition (i < n && i < MAX), constants, collection lengths and loops over a collection, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-606/",
	"languages": ["c", "cpp", "go", "java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [606],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["loop-bound", "cwe-606"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".go", ".java"}

_gate := `(?m)\b(?:atoi|atol|atoll|strto(?:u?ll?)|ntohl|ntohs|scanf|parseInt|valueOf|parseLong|nextInt|nextLong|Atoi|ParseInt|ParseUint)\s*\(|@(?:RequestParam|PathVariable|QueryParam|PathParam)\b`

_conv := `\b(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull|ntohl|ntohs)\s*\(|\b(?:Integer\.(?:parseInt|valueOf)|Long\.(?:parseLong|valueOf)|Short\.parseShort)\s*\(|\.next(?:Int|Long)\s*\(|\bstrconv\.(?:Atoi|ParseInt|ParseUint)\s*\(`

# Values an attacker or caller supplies.
_raw := `\bargv\s*\[|\bgetenv\s*\(|\boptarg\b|\bntoh[ls]\s*\(|\.getParameter\s*\(|\.getHeader\s*\(|\.getQueryString\s*\(|\.next(?:Int|Long)\s*\(|\.URL\.Query\(\)|\bFormValue\s*\(|\bPostFormValue\s*\(|\.Form\.Get\s*\(|\bHeader\.Get\s*\(|\bc\.(?:Query|DefaultQuery|Param|PostForm|GetHeader)\s*\(|\bmux\.Vars\s*\(|\bchi\.URLParam\s*\(|\bos\.Args\b|\bos\.Getenv\s*\(`

# The bound of a counted loop: for (...; i < N; ...), while (i < N), Go
# for i := 0; i < N; i++ and Go 1.22 for i := range N.
# Also the count-down forms while (n-- > 0), while (n--), while (--n >= 0)
# and for (; n > 0; n--), where the parsed value itself is the counter.
_loop := `(?:\bfor\b[^;{]*;\s*[A-Za-z_]\w*\s*<=?\s*([A-Za-z_]\w*)\s*(?:;|\))|\bwhile\s*\(\s*[A-Za-z_]\w*\s*<=?\s*([A-Za-z_]\w*)\s*\)|\bfor\s+[A-Za-z_]\w*\s*:?=\s*range\s+([A-Za-z_]\w*)\s*\{|\bwhile\s*\(\s*(?:--\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*--)\s*(?:>=?\s*0\s*)?\)|\bfor\b[^;{]*;\s*([A-Za-z_]\w*)\s*>\s*0\s*;\s*(?:--\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*--)\s*\)|\bfor\s+[A-Za-z_]\w*\s*<=?\s*([A-Za-z_]\w*)\s*\{)`

_bound(line) := n if {
	m := regex.find_all_string_submatch_n(_loop, line, 1)
	count(m) > 0
	some k in [1, 2, 3, 4, 5, 6, 7]
	n := m[0][k]
	n != ""
}

# Line j parses N from input.
_parsed_at(lines, j, n) if {
	line := lines[j]
	regex.match(_conv, line)
	helpers.assigned_first(line) == n
	regex.match(_raw, line)
}

_parsed_at(lines, j, n) if {
	line := lines[j]
	regex.match(_conv, line)
	helpers.assigned_first(line) == n
	not regex.match(_raw, line)
	some v in helpers.tainted_names(lines, j, 10, _raw)
	regex.match(concat("", [`\b`, v, `\b`]), line)
}

_parsed_at(lines, j, n) if {
	regex.match(concat("", [`\bscanf\s*\(\s*"[^"]*%[a-z]*[duil][^"]*"\s*,\s*&`, n, `\b`]), lines[j])
}

_parsed_at(lines, j, n) if {
	regex.match(concat("", [`@(?:RequestParam|PathVariable|QueryParam|PathParam)\b(?:\s*\([^)]*\))?\s*(?:final\s+)?(?:int|long|short|Integer|Long)\s+`, n, `\b`]), lines[j])
}

# A comparison or clamp of N between the parse and the loop.
_guarded(lines, j, i, n) if {
	some k in numbers.range(j, i - 1)
	line := lines[k]
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b(?:if|while|assert|require|check\w*)\b.*(?:\b`, n, `\s*(?:[<>]=?|>)|[<>]=?\s*`, n, `\b)`]), line)
}

_guarded(lines, j, i, n) if {
	some k in numbers.range(j, i - 1)
	regex.match(concat("", [`\b`, n, `\s*=\s*(?:Math\.)?\w*(?i:min|max|clamp|bound|limit|cap)\w*\s*\(`]), lines[k])
}

# N passed to min(...) between the parse and the loop (return Math.min(n, MAX)).
_guarded(lines, j, i, n) if {
	some k in numbers.range(j, i - 1)
	regex.match(concat("", [`\b(?:min|MIN)\s*\(\s*(?:[^,()]+,\s*)?`, n, `\b`]), lines[k])
}

# A function or method starts between the parse and the loop: the loop's N is
# another function's variable.
_guarded(lines, j, i, n) if {
	j + 1 < i
	some k in helpers.span(j + 1, i - 1)
	regex.match(`^(?:\s*func\s|\s*(?:(?:public|private|protected|static|final)\s+)+[\w<>\[\],.? ]+\s+\w+\s*\([^;]*\)\s*(?:throws\s[^{;]*)?\{?\s*$|[A-Za-z_][\w \*]*\b\w+\s*\([^;]*\)\s*\{?\s*$)`, lines[k])
	not regex.match(`^\s*(?:if|for|while|switch|else|catch|try|return|do|synchronized|go|defer)\b`, lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:for|while)\b`, line)
	not helpers.is_comment_line(line)
	n := _bound(line)
	not regex.match(`\b(?:for|while)\b.*(?:&&|\|\|)`, line)
	some j in numbers.range(max([0, i - 25]), i - 1)
	not helpers.is_comment_line(lines[j])
	_parsed_at(lines, j, n)
	not _guarded(lines, j, i, n)
	not _network_countdown(line, lines[j])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Loop bound '%s' is parsed from untrusted input and never checked against a maximum; cap it before looping", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A count-down loop over a value decoded from a network header (ntohs/ntohl):
# protocol code validates the message length before decoding its fields, in a
# function this rule cannot see, so only for/while (i < N) forms are judged
# for those.
_network_countdown(loop_line, parse_line) if {
	regex.match(`\bwhile\s*\(\s*(?:--\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*--)|;\s*[A-Za-z_]\w*\s*>\s*0\s*;`, loop_line)
	regex.match(`\bntoh[ls]\s*\(`, parse_line)
}

# N passed to a verify/validate/check function between the parse and the loop.
_guarded(lines, j, i, n) if {
	j + 1 < i
	some k in helpers.span(j + 1, i - 1)
	regex.match(concat("", [`(?i)\b\w*(?:verify|validate|check|sanitize|bound)\w*\s*\([^)]*\b`, n, `\b`]), lines[k])
}
