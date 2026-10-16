# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_807

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-807",
	"name": "Reliance on Untrusted Inputs in a Security Decision",
	"description": "Reports an authorization decision taken on a value the client sends and can set to anything: an if/elif/else-if/switch condition, or a boolean assignment with a comparison, that reads a cookie, request header, query, body or path parameter (Express req.cookies/headers/query/body/params, with optional chaining, req.get()/req.header(); Flask/Django request.cookies/COOKIES/headers/META/args/GET/POST/form/values; Java request.getParameter/getHeader on any request or req variable, a Cookie from getCookies() compared by getName()/getValue(), Spring @RequestHeader/@CookieValue/@RequestParam parameters; FastAPI Header()/Cookie()/Query() parameters) where the input's name says what it decides (admin, role, root, superuser, staff, privilege, permission, access level, authenticated, authorized, logged-in) or it is compared with a privileged literal ('admin', 'administrator', 'root', 'superuser', 'staff', 'owner', 'moderator', 'auditor'). The value may be read on the same line, assigned to a variable up to 15 lines above, or destructured from the request object (const { role } = req.cookies). Not reported: server-side state (req.session, req.signedCookies, req.user, request.user, request.getSession(), isUserInRole), a condition that also consults server-side identity (req.body.role === 'admin' && !req.user.isAdmin, which guards against escalation), inputs that decide nothing privileged (theme, language, a non-empty check), logging or passing the value on without a decision, Referer/User-Agent checks, credential comparisons, string literals, comments and test files. A cookie named for a privilege or login state that is compared or tested on its line, or assigned to a variable a condition uses within 15 lines, is reported by VNX-784 (a security decision on a cookie) and not here; other cookies, headers and parameters stay with this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-807/",
	"languages": ["java", "node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [807],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["security-critical-input", "cwe-807", "authorization"],
}

_ext := {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".java"}

_in_scope(path) if {
	some e in _ext
	endswith(path, e)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
}

_gate := `(?:\breq|\brequest)\.(?:cookies|headers|query|body|params|get|header|COOKIES|args|GET|POST|form|values|META|query_params)\b|getParameter\s*\(|getHeader\s*\(|getCookies\s*\(|@(?:RequestHeader|CookieValue|RequestParam)\b|\b(?:Header|Cookie)\s*\(`

# Client-controlled reads; group 1 or 2 is the input's name.
_src_res := [
	`\b(?:req|request)\.(?:cookies|headers|query|body|params)\s*(?:\??\.\s*([\w$]+)|(?:\?\.)?\[\s*['"\x60]([^'"\x60]+)['"\x60]\s*\])`,
	`\b(?:req|request)\.(?:get|header)\s*\(\s*['"\x60]([^'"\x60]+)['"\x60]()`,
	`\brequest\.(?:COOKIES|cookies|headers|args|GET|POST|form|values|META|query_params)\s*(?:\.\s*get\s*\(\s*['"]([^'"]+)['"]|\[\s*['"]([^'"]+)['"]\s*\])`,
	`\b(?:\w*[Rr]equest|req)\s*\.\s*(?:getParameter|getHeader)\s*\(\s*"([^"]+)"()`,
	`\.getName\s*\(\s*\)\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*"([^"]+)"()`,
	`"([^"]+)"\s*\.\s*equals(?:IgnoreCase)?\s*\(\s*\w+\s*\.\s*getName\s*\(\s*\)()`,
]

_src_any := `\b(?:req|request)\.(?:cookies|headers|query|body|params)\b|\b(?:req|request)\.(?:get|header)\s*\(\s*['"\x60]|\brequest\.(?:COOKIES|cookies|headers|args|GET|POST|form|values|META|query_params)\b|\b(?:\w*[Rr]equest|req)\s*\.\s*(?:getParameter|getHeader)\s*\(`

_priv_name := `(?i)(admin|role|root|superuser|staff|privilege|permission|access_?level|authenticated|authori[sz]ed|auth_?level|logged_?in|is_?auth)`

_lits := `(?:admin\w*|administrator|root|superuser|super_?admin|staff|owner|moderator|auditor|privileged)`

_priv_literal := concat("", [`(?i)(?:===?|!==?|\.equals(?:IgnoreCase)?\s*\(|\bin\s*[\(\[\{])\s*['"]`, _lits, `['"]|['"]`, _lits, `['"]\s*(?:===?|!==?|\.equals)`])

_not_trust := `(?i)^(?:http_)?(?:referer|referrer|user-agent|user_agent)$`

_decision(line) if regex.match(`^\s*(?:\}\s*)?(?:if|elif|else\s+if|while|switch)\b`, line)

_decision(line) if {
	regex.match(`^\s*(?:const|let|var|final|boolean|bool|[A-Za-z_]\w*)?\s*[A-Za-z_]\w*\s*(?::\s*\w+\s*)?=\s*!?\(?\s*\w`, line)
	regex.match(`===?|!==?|\.equals(?:IgnoreCase)?\s*\(`, line)
	regex.match(_src_any, line)
}

_names(line) := {n |
	some re in _src_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	n := concat("", [m[1], m[2]])
	n != ""
}

_cookie_file(content) if contains(content, "getCookies(")

# Shape 1: the decision reads the input directly.
_direct_hits(content, line) := {n |
	some n in _names(line)
	not regex.match(_not_trust, n)
	not _is_cookie_getter_only(content, line)
	_priv_direct(n, line)
}

_priv_direct(n, _) if regex.match(_priv_name, n)

_priv_direct(_, line) if regex.match(_priv_literal, line)

# getName() comparisons only mean a cookie when the file iterates getCookies().
_is_cookie_getter_only(content, line) if {
	not regex.match(_src_any, line)
	not _cookie_file(content)
}

_direct_rhs := concat("", [`[^=!<>]=\s*(?:await\s+)?\(?\s*(?:`, _src_any, `)`])

_assign_re := `^\s*(?:(?:const|let|var|final)\s+)?(?:[A-Za-z_][\w<>\[\]]*\s+)?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]|]+\s*)?=[^=]`

# Variables assigned from a client-controlled read in the 15 lines above.
_tainted_assign(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	regex.match(_src_any, l)
	regex.match(_direct_rhs, l)
	m := regex.find_all_string_submatch_n(_assign_re, l, 1)
	count(m) > 0
	v := m[0][1]
	not regex.match(_not_trust, v)
}

# Spring handler parameters bound from a header, cookie or parameter.
_tainted_spring(lines, i) := {v |
	some j in numbers.range(max([0, i - 12]), i - 1)
	some m in regex.find_all_string_submatch_n(`@(?:RequestHeader|CookieValue|RequestParam)\b\s*(?:\([^)]*\))?\s*(?:final\s+)?[\w<>\[\]]+\s+([A-Za-z_]\w*)`, lines[j], -1)
	v := m[1]
}

# Shape 2: the decision reads a variable assigned from the input.
_var_hits(lines, i, line) := {v |
	some v in (_tainted_assign(lines, i) | _tainted_spring(lines, i)) | (_tainted_destructured(lines, i) | _tainted_fastapi(lines, i))
	regex.match(concat("", [`(?:^|[^\w.$])`, v, `\b`]), line)
	_priv_var(v, line)
}

_priv_var(v, _) if regex.match(_priv_name, v)

_priv_var(_, line) if regex.match(_priv_literal, line)

findings contains finding if {
	some path, content in input.file_contents
	_in_scope(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	_decision(line)
	not helpers.is_comment_line(line)
	not regex.match(`(?i)passw|\bpwd\b`, line)
	not regex.match(_server_side, line)
	hits := _direct_hits(content, line) | _var_hits(lines, i, line)
	count(hits) > 0
	not _c784_owned(path, lines, i, line)
	n := min(hits)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Authorization decided by client-controlled input %q (cookie, header or request parameter): a client sets it to whatever passes the check. Decide on server-side session or identity state instead", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Server-side identity or session state consulted in the same condition: the
# client value is checked against it rather than trusted
# (`req.body.role === 'admin' && !req.user.isAdmin`).
_server_side := `\b(?:req\.(?:user|session|signedCookies)|request\.(?:user|session)|session\s*\[|getSession\s*\(|getUserPrincipal\s*\(|isUserInRole\s*\(|hasRole\s*\(|hasAuthority\s*\(|current_user\b|g\.user\b)`

# const { role, isAdmin: admin = false } = req.cookies;
_tainted_destructured(lines, i) := {v |
	some j in numbers.range(max([0, i - 15]), i - 1)
	l := lines[j]
	contains(l, "{")
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:req|request|ctx\.request)\.(?:cookies|headers|query|body|params)\b`, l, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	p := trim_space(split(part, "=")[0])
	p != ""
	names := split(p, ":")
	v := trim_space(names[count(names) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

# FastAPI handler parameters bound from a header, cookie or query value.
_tainted_fastapi(lines, i) := {v |
	some j in numbers.range(max([0, i - 12]), i - 1)
	l := lines[j]
	regex.match(`\b(?:Header|Cookie|Query)\s*\(`, l)
	some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*:\s*(?:[^=,()]*?=\s*(?:Header|Cookie|Query)\s*\(|Annotated\s*\[[^\]]*\b(?:Header|Cookie|Query)\s*\()`, l, -1)
	v := m[1]
}

# ── Lines VNX-784 reports ───────────────────────────────────────────────
# A raw read of a cookie named for a privilege or login state that is
# compared or tested on its line, or assigned to a variable a condition uses
# within the next 15 lines, is a security decision on a cookie: VNX-784
# (CWE-784) reports it, so this rule leaves the line to it. This mirrors
# VNX-784's Python, JavaScript/TypeScript and PHP reads.
_c784_lang(path) := "py" if endswith(path, ".py")

_c784_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx|mts|cts)$`, path)

_c784_lang(path) := "php" if endswith(path, ".php")

_c784_priv := {
	"admin", "isadmin", "adminmode", "role", "roles", "userrole", "staff", "isstaff",
	"superuser", "issuperuser", "isroot", "privilege", "privileges", "accesslevel",
	"userlevel", "authlevel", "usertype", "accounttype", "usergroup", "loggedin",
	"isloggedin", "authenticated", "isauthenticated", "authorized", "isauthorized",
	"permission", "permissions",
}

_c784_reads := {
	"py": [
		`\b\w*request\.(?:COOKIES|cookies)(?:\.get\(\s*["']([\w-]+)["']|\[\s*["']([\w-]+)["']\s*\])`,
		`\.get_cookie\(\s*["']([\w-]+)["']`,
		`["']([\w-]+)["']\s+(?:not\s+)?in\s+\w*request\.(?:COOKIES|cookies)\b`,
	],
	"js": [
		`\b(?:req|request|ctx|ctx\.request)\.cookies(?:\.get\(\s*["']([\w-]+)["']|\[\s*["']([\w-]+)["']\s*\]|\.([A-Za-z_$][\w$]*)\b)`,
		`\bcookies\(\)\.get\(\s*["']([\w-]+)["']`,
	],
	"php": [
		`\$_COOKIE\[\s*["']([\w-]+)["']\s*\]`,
		`\bfilter_input\(\s*INPUT_COOKIE\s*,\s*["']([\w-]+)["']`,
	],
}

_c784_owned(path, lines, i, line) if {
	lang := _c784_lang(path)
	contains(lower(line), "cookie")
	not helpers.is_comment_line(line)
	not regex.match(`\bsigned\s*:\s*true\b|\bsecret\s*=`, line)
	some re in _c784_reads[lang]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	ns := [g | some j, g in m; j > 0; g != ""]
	count(ns) > 0
	regex.replace(lower(ns[0]), `[_-]`, "") in _c784_priv
	idx := indexof(line, m[0])
	prefix := substring(line, 0, idx)
	not _c784_in_string(prefix)
	_c784_report(lines, i, line, prefix, substring(line, idx + count(m[0]), -1))
}

_c784_in_string(prefix) if {
	some q in {`"`, "'", "`"}
	n := count(indexof_n(prefix, q)) - count(indexof_n(prefix, concat("", [`\`, q])))
	n % 2 == 1
}

_c784_report(_, _, _, prefix, suffix) if _c784_decides(prefix, suffix)

_c784_report(lines, i, line, prefix, suffix) if {
	not _c784_decides(prefix, suffix)
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|my)\s+|[A-Za-z_][\w<>\[\]*.]*\s+)?(\$?[A-Za-z_]\w*)\s*(?:,\s*\w+\s*)*(?::\s*\w+\s*)?(?::=|=)[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
	v != "_"
	end := min([count(lines) - 1, i + 15])
	end >= i + 1
	ve := replace(v, "$", `\$`)
	some k in numbers.range(i + 1, end)
	l := lines[k]
	not helpers.is_comment_line(l)
	contains(l, trim_left(v, "$"))
	regex.match(concat("", [
		`(?:^|[\s(])(?:if|elif|elsif|unless|while|when|case|switch)\b[^\n]*(?:^|[^\w$])`, ve, `\b`,
		`|(?:^|[^\w$])`, ve, `\b(?:\.Value)?\s*(?:===?|!==?)`,
		`|(?:===?|!==?|\.equals\()\s*`, ve, `\b`,
	]), l)
}

_c784_decides(prefix, suffix) if {
	regex.match(`^\s*(?:\)\s*)?(?:===?|!==?|>=?|<=?|\.equals\(|\?[^?.])`, suffix)
	not regex.match(`\b(?:isset|empty|array_key_exists)\s*\(\s*$`, prefix)
}

_c784_decides(prefix, _) if regex.match(`(?:===?|!==?|\.equals\(|\bin_array\()\s*$`, prefix)

_c784_decides(prefix, _) if regex.match(`(?:(?:^|[\s(])(?:if|elif|elsif|unless|while|and|or|not)|&&|\|\|)\s*\(?\s*!?\s*$`, prefix)
