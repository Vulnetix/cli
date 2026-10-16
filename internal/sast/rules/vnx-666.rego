# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_666

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-666",
	"name": "HTTP response written after it was already sent",
	"description": "An Express, Koa-style or Fastify handler finishes the response (res/response/reply .send, .json, .jsonp, .end, .redirect, .render, .sendFile, .sendStatus or .download, also at the end of a .status(...)/.code(...) chain) and does not return, so the next statement writes to the same response again: either the very next statement, or the first response write at the same level after the closing brace of the if- or catch-block the response was sent in, before any return/throw/else/case boundary or the end of the enclosing block (the missing 'return' after an error reply), including after a braceless one-line `if (...) res.send(...)`; the second write may itself be 'return res.json(...)'. The second write runs in the wrong phase of the response's lifetime: it throws ERR_HTTP_HEADERS_SENT or is silently lost, and the code after the error reply (the success path) still executes. The finding is on the first, unreturned send. Not reported: a send preceded by 'return' or followed by a return/break statement, if/else branches, a send whose block is followed by '} else', '});' (a callback) or '},' (an object of handlers), res.write() streaming followed by res.end(), sends in comments and string literals. Python and other languages are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-666/",
	"languages": ["node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [666],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["operation-on-wrong-resource", "cwe-666", "express", "response"],
}

_exts := [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]

_terminal := `send|json|jsonp|end|redirect|render|sendFile|sendStatus|download`

_again := `send|json|jsonp|end|redirect|render|sendFile|sendStatus|download|write|writeHead|setHeader|set|header|cookie|status|code|type|location|attachment|append`

# A statement (optionally behind a braceless `if (...)`) that ends the response:
# `res.send(x)`, `res.status(404).json({...})`, `reply.code(404).send(...)`.
_send_re := concat("", [
	`^\s*(?:if\s*\(.*\)\s*)?(?:await\s+)?(res|response|reply|resp)\.(?:(?:status|code|type|set|header|cookie)\([^;]*?\)\.)*(?:`,
	_terminal,
	`)\s*\(`,
])

_write_re(recv) := concat("", [`^\s*(?:return\s+)?(?:await\s+)?`, recv, `\.(?:`, _again, `)\s*\(`])

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(s) := regex.replace(regex.replace(regex.replace(s, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`), "`(?:[^`\\\\]|\\\\.)*`", "``")

_balance(s) := strings.count(t, "(") - strings.count(t, ")") if t := _strip(s)

# The last line of the statement opened at line i (parentheses balanced).
_stmt_end(lines, i) := i if _balance(lines[i]) <= 0

_stmt_end(lines, i) := e if {
	_balance(lines[i]) > 0
	end := min([count(lines) - 1, i + 15])
	i + 1 <= end
	cands := [k |
		some k in numbers.range(i + 1, end)
		sum([_balance(lines[m]) | some m in numbers.range(i, k)]) <= 0
	]
	count(cands) > 0
	e := cands[0]
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	regex.match(`\b(?:res|response|reply|resp)\.`, content)
	regex.match(concat("", [`(?m)`, _send_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_send_re, line)
	not contains(line, "else")
	not _in_block_comment(lines, i)
	m := regex.find_all_string_submatch_n(_send_re, line, 1)
	recv := m[0][1]
	e := _stmt_end(lines, i)
	j := helpers.next_code_index(lines, e, 4)
	k := _second_write(lines, i, j, recv)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The response is sent here without a 'return', and line %d writes to it again: that write throws ERR_HTTP_HEADERS_SENT (or is lost) and the code after the reply still runs. Return after sending", [k + 1]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The very next statement writes the same response again.
_second_write(lines, i, j, recv) := j if {
	regex.match(_write_re(recv), lines[j])
	_indent(lines[j]) == _indent(lines[i])
}

# Inside a /* ... */ block opened on an earlier line.
_in_block_comment(lines, i) if {
	start := max([0, i - 30])
	i > start
	marks := [j | some j in numbers.range(start, i - 1); _comment_mark(lines[j])]
	count(marks) > 0
	l := lines[max(marks)]
	contains(l, "/*")
	not contains(substring(l, indexof(l, "/*"), -1), "*/")
}

_comment_mark(l) if contains(l, "/*")

_comment_mark(l) if contains(l, "*/")

# The send closes an if-block (or catch-block); the first statement at the
# block's own level after it that writes the same response again, unless a
# return/throw/else/case boundary or the end of the enclosing block comes first.
_second_write(lines, i, j, recv) := k if {
	trim_space(lines[j]) == "}"
	ind := _indent(lines[j])
	ind < _indent(lines[i])
	n := count(lines) - 1
	j + 1 <= n
	outer := [t |
		some t in numbers.range(j + 1, min([n, j + 15]))
		trim_space(lines[t]) != ""
		not helpers.is_comment_line(lines[t])
		_indent(lines[t]) <= ind
	]
	firsts := [t |
		some t in outer
		_outer_decides(lines, t, ind, recv)
	]
	count(firsts) > 0
	k := firsts[0]
	_indent(lines[k]) == ind
	regex.match(_write_re(recv), lines[k])
}

_outer_decides(lines, t, ind, recv) if regex.match(_write_re(recv), lines[t])

_outer_decides(lines, t, ind, _) if _indent(lines[t]) < ind

_outer_decides(lines, t, _, _) if regex.match(`^\s*(?:\}\s*)?(?:else|catch|finally|case|default|return|throw|break|continue)\b`, lines[t])

# A braceless `if (...) res.status(404).send(...)`: the send is conditional and
# the statements after it still run, so the first response write at the same
# level (before a return/throw/else/case boundary or the end of the block) is
# the second write.
_second_write(lines, i, j, recv) := k if {
	regex.match(`^\s*if\s*\(`, lines[i])
	ind := _indent(lines[i])
	n := count(lines) - 1
	i + 1 <= n
	outer := [t |
		some t in numbers.range(i + 1, min([n, i + 15]))
		trim_space(lines[t]) != ""
		not helpers.is_comment_line(lines[t])
		_indent(lines[t]) <= ind
	]
	firsts := [t |
		some t in outer
		_outer_decides(lines, t, ind, recv)
	]
	count(firsts) > 0
	k := firsts[0]
	_indent(lines[k]) == ind
	regex.match(_write_re(recv), lines[k])
}
