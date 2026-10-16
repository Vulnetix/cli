# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_602

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-602",
	"name": "Server trusts a client-supplied role or admin flag",
	"description": "A server-side authorisation decision is taken on a value the client controls: a request body field, query parameter, URL parameter, header or unsigned cookie named for a role or privilege (admin, isAdmin, is_admin, role, user_role, X-User-Role, isAuthenticated, loggedIn, authorized, privileges, accessLevel, userType, permissions, isStaff, superuser) is compared (including <, >= against a level), tested in a condition, searched with in or used in a ternary, either directly or through a variable assigned (or destructured: const { isAdmin } = req.body) from it within the 15 lines above; PHP if (!empty($_POST['is_admin'])) on a boolean privilege flag counts as a test. The client sets these values, so the check enforces nothing the client did not already decide. Covers Express/Koa (req.body, req.query, req.params, req.headers, req.cookies), Django/Flask (request.COOKIES/GET/POST/args/form/cookies/headers/json/values/data) and PHP ($_COOKIE, $_GET, $_POST, $_REQUEST, $_SERVER). Not reported: server-held identity (req.user, req.session, request.user, $_SESSION), signed cookies, the Authorization header, presence checks (isset, compared with null/undefined/None), assignment without a decision (role written to a new record), allowlist validation (includes), comparisons inside filter/find callbacks or comprehensions (filtering records by a requested role), browser UI code reading a user object, comments and string literals. A privilege or login-state cookie that is compared or tested on its line, or assigned to a variable a condition uses within 15 lines, is reported by VNX-784 (a security decision on a cookie) and not here; body, query, URL-parameter and header values stay with this rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-602/",
	"languages": ["node", "python", "php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [602],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["authorization", "client-side-enforcement", "trust-boundary", "cwe-602"],
}

_name := `(?i:(?:http_)?(?:x[-_])?(?:(?:is|user|account)[-_]?)?(?:admin|role|roles|authenticated|logged[-_]?in|authori[sz]ed|privileges?|access[-_]?level|permissions|staff|superuser)|(?:user|account)[-_]?type)`

# Matched against the normalised line (see _norm): keys become members.
_access := concat("", [
	`(?:\breq(?:uest)?\.(?:body|query|params|headers|cookies)\.`, _name,
	`|\brequest\.(?:COOKIES|GET|POST|args|form|cookies|headers|json|values|data|query_params)(?:\.get\(\s*`, _name, `\s*[,)]|\.`, _name,
	`)|\$_(?:COOKIE|GET|POST|REQUEST|SERVER)\.`, _name, `)(?:[^\w-]|$)`,
])

_ext := {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".php"}

_ext_of(path) := concat("", [".", parts[count(parts) - 1]]) if parts := split(path, ".")

# ['key'] → .key and get('key' → get(key, then every other literal → "".
_norm(line) := n if {
	a := regex.replace(line, `\[\s*['"]([\w-]+)['"]\s*\]`, ".$1")
	b := regex.replace(a, `\.get\(\s*['"]([\w-]+)['"]`, ".get($1")
	n := regex.replace(b, "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`", `""`)
}

_msg := "An authorisation decision uses a role or admin flag the client sent (body, query, header or cookie); the client can set it to anything. Decide from the server-side session or verified identity instead"

findings contains finding if {
	some path, content in input.file_contents
	_ext_of(path) in _ext
	_file_gate(content)
	lines := split(content, "\n")
	srcs := [j | some j, l in lines; _raw_access(l)]
	count(srcs) > 0
	some i in _decision_lines(lines, srcs)
	not _c784_owned(path, lines, i, lines[i])
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

_file_gate(content) if contains(content, "req.")

_file_gate(content) if contains(content, "request.")

_file_gate(content) if contains(content, "$_")

_raw_access(l) if {
	regex.match(`\b(?:req|request)\.(?:body|query|params|headers|cookies|COOKIES|GET|POST|args|form|json|values|data|query_params)\b|\$_(?:COOKIE|GET|POST|REQUEST|SERVER)\s*\[`, l)
	not helpers.is_comment_line(l)
}

_cmp := `(?:===?|!==?|<>)`

_nullish := `(?:null|undefined|None|NULL)\b`

_decision_lines(lines, srcs) := ((direct | indirect) | destructured) | php_flag if {
	norms := {j: _norm(lines[j]) | some j in srcs}
	php_flag := {j | some j in srcs; regex.match(_php_flag_re, norms[j])}
	direct := {j | some j in srcs; regex.match(_access, norms[j]); _used_as_decision(norms[j], _access); not _filtering(norms[j])}
	destructured := {i |
		some j in srcs
		some v in _destructured(lines[j])
		some i in numbers.range(j + 1, min([count(lines) - 1, j + 15]))
		contains(lines[i], v)
		not helpers.is_comment_line(lines[i])
		n := _norm(lines[i])
		_used_as_decision(n, concat("", [`(?:^|[^\w$.])`, v, `\b`]))
		not _filtering(n)
	}
	indirect := {i |
		some j in srcs
		p := norms[j]
		not j in direct
		regex.match(_access, p)
		not regex.match(`(?:isset|empty)\s*\(`, p)
		m := regex.find_all_string_submatch_n(`^\s*(?:(?:const|let|var|final)\s+)?\$?([A-Za-z_]\w*)\s*(?::\s*[\w<>\[\]|]+\s*)?=[^=]`, p, 1)
		count(m) > 0
		v := m[0][1]
		some i in numbers.range(j + 1, min([count(lines) - 1, j + 15]))
		contains(lines[i], v)
		not helpers.is_comment_line(lines[i])
		_used_as_decision(_norm(lines[i]), concat("", [`(?:^|[^\w$.])\$?`, v, `\b`]))
		not _filtering(_norm(lines[i]))
	}
}


_used_as_decision(n, x) if {
	regex.match(concat("", [x, `\s*(?:\)\s*)?`, _cmp, `\s*(?:[^\s\w]|\w)`]), n)
	not regex.match(concat("", [x, `\s*(?:\)\s*)?`, _cmp, `\s*`, _nullish]), n)
	not _presence(n, x)
}

_used_as_decision(n, x) if {
	regex.match(concat("", [_cmp, `\s*`, x]), n)
	not regex.match(concat("", [_nullish, `\s*`, _cmp, `\s*`, x]), n)
	not _presence(n, x)
}

# if (req.body.isAdmin) / if not request.COOKIES.get(admin): / cond ? a : b
_used_as_decision(n, x) if {
	regex.match(concat("", [`^\s*(?:\}\s*)?(?:else\s*)?(?:if|elif|elseif|while)\s*\(?\s*(?:!|not\s+)?\s*`, x, `\s*(?:\)\s*\{?|:|\{|&&|\|\||and\b|or\b)`]), n)
	not _presence(n, x)
}

_used_as_decision(n, x) if {
	regex.match(concat("", [x, `\s*\?[^?.:]`]), n)
	not _presence(n, x)
}

# Membership test on a request-supplied collection: if "export" not in privileges
_used_as_decision(n, x) if {
	regex.match(concat("", [`^\s*(?:\}\s*)?(?:else\s*)?(?:if|elif|elseif|while|assert)\b[^\n]*\bin\b[^\n]*?`, x]), n)
	not _presence(n, x)
}

# Numeric comparison against a level: if ($level >= 3)
_used_as_decision(n, x) if {
	regex.match(concat("", [`\b(?:if|elif|elseif|while)\b[^\n]*`, x, `\s*(?:>=|<=|>|<)\s*\d`]), n)
	not _presence(n, x)
}

_used_as_decision(n, x) if {
	regex.match(concat("", [`\b(?:if|elif|elseif|while)\b[^\n]*\d\s*(?:>=|<=|>|<)\s*`, x]), n)
	not _presence(n, x)
}

_presence(n, x) if regex.match(concat("", [`(?:isset|empty|typeof)\s*\(?\s*`, x]), n)

# A comparison inside a collection callback or comprehension filters records
# by the requested role; it grants nothing.
_filtering(n) if regex.match(`\.(?:filter|find|findIndex|findOne|some|every|where|count)\s*\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>|\bfor\s+\w+\s+in\b.*\bif\b`, n)

# const { isAdmin, role: r } = req.body;  →  isAdmin, r (names for a role or flag).
_destructured(l) := {v |
	m := regex.find_all_string_submatch_n(`^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\.(?:body|query|params|headers|cookies)\b`, l, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	kv := split(trim_space(part), ":")
	regex.match(concat("", [`^`, _name, `$`]), trim_space(kv[0]))
	v := trim_space(kv[count(kv) - 1])
	regex.match(`^[A-Za-z_$][\w$]*$`, v)
}

# PHP if (!empty($_POST['is_admin'])): empty() is the truthiness test there, so
# for a boolean privilege flag (not a role name, often validated as required)
# it is the decision itself.
_php_flag_re := `^\s*(?:\}\s*)?(?:else\s*)?(?:if|elseif)\s*\(\s*!\s*empty\s*\(\s*\$_(?:COOKIE|GET|POST|REQUEST|SERVER)\.(?i:(?:is_?)?(?:admin|authenticated|logged_?in|authori[sz]ed|staff|superuser))\s*\)`

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
