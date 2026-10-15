# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_698

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-698",
	"name": "Execution After Redirect (EAR)",
	"description": "A handler sends a redirect (typically to the login page when an access check fails) but does not stop, so the code after it still runs: the protected action is performed, or the protected page is rendered into the body of the redirect response, for any client that ignores the Location header. Reported: PHP header('Location: ...') (any case, any quotes) and WordPress wp_redirect()/wp_safe_redirect() whose next statement is ordinary code rather than exit/die/return/throw (also when the redirect closes an if block and code follows the block); Laravel redirect(...), redirect()->... and Redirect::... called as a bare statement in a file that uses Illuminate, which builds a response and discards it; Flask/Django/Starlette redirect(...), HttpResponseRedirect(...), HttpResponsePermanentRedirect(...) and RedirectResponse(...) called as a bare statement (not returned, assigned or raised), which does nothing at all. Not reported: a redirect followed by exit, die, return, throw or break (also on the same line, and with comments or further header()/setcookie() calls between), a redirect that ends a helper function (the caller decides), a redirect followed by an else branch or by ?>, returned or assigned redirects, Laravel redirect()->setIntendedUrl(...) (which stores the intended URL and builds no response), bottle's redirect() (which raises), plain PHP files that define their own redirect() helper, test files, comments and string literals. Ruby on Rails redirect_to is not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-698/",
	"languages": ["php", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [698],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["execution-after-redirect", "cwe-698"],
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_is_code(line) if {
	trim_space(line) != ""
	not helpers.is_comment_line(line)
}

# ── PHP header('Location') / wp_redirect ─────────────────────────────────

_php_redirect := `(?i)^\s*(?:@\s*)?\\?(?:header\s*\(\s*["']\s*location\s*:|wp_(?:safe_)?redirect\s*\()`

_terminator := `^\s*\}?\s*(?:(?:exit|die)\b|return\b|throw\b|break\b|continue\b)`

# Calls that belong to sending the redirect and are not "execution after" it.
_redirect_part := `(?i)^\s*(?:@\s*)?\\?(?:header|setcookie|session_write_close|http_response_code|ob_end_\w+|ob_flush|flush)\s*\(`

_closer := `^\s*\}\s*;?\s*$|^\s*end(?:if|foreach|for|while|switch)\s*;`

_else_like := `^\s*\}?\s*(?:else|elseif|catch|finally)\b`

_next_code(lines, i) := [k |
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 12]))
	_is_code(lines[k])
]

# The first line after i that is not part of sending the redirect.
_next_stmt(lines, i) := k if {
	ks := [k | some k in _next_code(lines, i); not regex.match(_redirect_part, lines[k])]
	count(ks) > 0
	k := ks[0]
}

# The block holding line i was opened by a function declaration.
_in_function_block(lines, i) if {
	ii := _indent(lines[i])
	opens := [k |
		some k in numbers.range(max([0, i - 40]), i - 1)
		_is_code(lines[k])
		_indent(lines[k]) < ii
	]
	count(opens) > 0
	o := opens[count(opens) - 1]
	_function_opener(lines, o)
}

_function_opener(lines, o) if regex.match(`\bfunction\b|\bfn\s*\(`, lines[o])

# a `{` on its own line under a function signature
_function_opener(lines, o) if {
	regex.match(`^\s*\{\s*$`, lines[o])
	o > 0
	regex.match(`\bfunction\b`, lines[o - 1])
}

_after_redirect(lines, i) := k if {
	k := _next_stmt(lines, i)
	not regex.match(_terminator, lines[k])
	not regex.match(_closer, lines[k])
	not regex.match(_else_like, lines[k])
	not startswith(trim_space(lines[k]), "?>")
}

_after_redirect(lines, i) := m if {
	k := _next_stmt(lines, i)
	regex.match(_closer, lines[k])
	not _in_function_block(lines, i)
	ms := _next_code(lines, k)
	count(ms) > 0
	m := ms[0]
	not regex.match(_terminator, lines[m])
	not regex.match(_closer, lines[m])
	not regex.match(_else_like, lines[m])
	not regex.match(_redirect_part, lines[m])
	not startswith(trim_space(lines[m]), "?>")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	regex.match(`(?i)location\s*:|wp_(?:safe_)?redirect`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_php_redirect, line)
	rest := _code(line)
	not regex.match(`;\s*(?:exit|die|return|throw)\b|\bor\s+(?:die|exit)\b`, rest)
	_after_redirect(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Redirect sent without exit/die: the statements after it still execute, and their output reaches the client in the redirect body",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Bare redirect calls whose response is discarded ──────────────────────

_continued(prev) if regex.match(`(?:[(\[,=\\]|->|\breturn|\byield|\braise|\band|\bor)\s*$`, prev)

_prev_code(lines, i) := lines[k] if {
	ks := [j | some j in numbers.range(max([0, i - 4]), i - 1); _is_code(lines[j])]
	count(ks) > 0
	k := ks[count(ks) - 1]
}

_not_continuation(lines, i) if i == 0

_not_continuation(lines, i) if {
	i > 0
	not _prev_code(lines, i)
}

_not_continuation(lines, i) if {
	i > 0
	not _continued(_prev_code(lines, i))
}

_py_frameworks := `(?m)^\s*(?:from\s+(?:flask|django\.shortcuts|django\.http|starlette\.responses|fastapi\.responses|quart|werkzeug\.utils)\s+import\b|import\s+(?:flask|django)\b)`

_py_bare := `^\s*(?:flask\.|shortcuts\.)?(?:redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	not helpers.is_test_path(path)
	contains(content, "edirect")
	regex.match(_py_frameworks, content)
	not regex.match(`(?m)^\s*(?:from\s+bottle\s+import|import\s+bottle)\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_py_bare, line)
	_not_continuation(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The redirect response is built and discarded (not returned), so no redirect happens and the handler carries on",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_laravel_bare := `^\s*(?:redirect\s*\(|\\?Redirect::\w+\s*\()`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	not helpers.is_test_path(path)
	contains(content, "edirect")
	regex.match(`(?m)^\s*use\s+Illuminate\\`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_laravel_bare, line)
	# Redirector calls that configure the session rather than build a response.
	not regex.match(`(?:->|::)\s*(?:setIntendedUrl|setSession|getUrlGenerator)\s*\(`, line)
	_not_continuation(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The redirect response is built and discarded (not returned), so no redirect happens and the action carries on",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
