package vulnetix.rules.vnx_jwt_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JWT-003",
	"name": "JWT signing with hardcoded secret",
	"description": "A JWT signing or verification key is a string literal in source or committed config, so anyone with the repository can forge valid tokens. Reported: a literal key passed directly to jsonwebtoken jwt.sign/verify, express-jwt { secret: '...' }, PyJWT/python-jose jwt.encode/decode (positional or key=), ruby-jwt JWT.encode/decode, firebase/php-jwt JWT::encode and new Key('...'), jjwt signWith/setSigningKey, Auth0 Algorithm.HMAC256/384/512, Keys.hmacShaKeyFor, golang-jwt SignedString([]byte(\"...\")) and .NET new SymmetricSecurityKey(Encoding.X.GetBytes(\"...\")); a variable assigned a literal in the same file and then passed as the key to one of those calls; and an assignment of a literal to a JWT-named setting (JWT_SECRET, JWT_SECRET_KEY, jwtSecret, jwt_signing_key, jwtKey, app.config[\"JWT_SECRET_KEY\"]) in code, .env, .properties or YAML. Not reported: keys read from the environment, configuration or a secrets manager, placeholders (changeme, <...>, ${...}, your-...), non-secret JWT settings (JWT_ALGORITHM, a setting's name), test files and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-jwt-003/",
	"languages": ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp", "properties"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["jwt", "secrets", "credentials"],
}

_lang(path) := "js" if regex.match(`\.(?:js|mjs|cjs|jsx|ts|tsx)$`, path)

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "java" if endswith(path, ".kt")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "rb" if endswith(path, ".rb")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "cs" if endswith(path, ".cs")

_lang(path) := "conf" if regex.match(`(?:^|/)\.env(?:\.[\w-]+)?$`, path)

_lang(path) := "conf" if regex.match(`\.(?:properties|ya?ml)$`, path)

_template(path) if regex.match(`(?i)\.(?:example|sample|template|dist|tmpl)$|(?:^|/)\.env\.(?:example|sample|template|dist)$`, path)

# Calls whose key argument is captured as a literal (group 1).
_lit_sinks := {
	"js": [
		`\b(?:jwt|jsonwebtoken|JWT)\.(?:sign|verify)\s*\(\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*['"\x60]([^'"\x60]+)['"\x60]`,
		`\b(?:expressjwt|expressJwt|jwt)\s*\(\s*\{[^}]*\bsecret\s*:\s*['"\x60]([^'"\x60]+)['"\x60]`,
	],
	"py": [
		`\bjwt\.(?:encode|decode)\s*\(\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*['"]([^'"]+)['"]`,
		`\bjwt\.(?:encode|decode)\s*\((?:[^()]|\([^()]*\))*?\bkey\s*=\s*['"]([^'"]+)['"]`,
	],
	"rb": [`\bJWT\.(?:encode|decode)(?:\s*\(\s*|\s+)(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*['"]([^'"]+)['"]`],
	"php": [
		`\bJWT::(?:encode|decode)\s*\(\s*(?:\[(?:[^\[\]]|\[[^\[\]]*\])*\]|[^,\[\]]+?)\s*,\s*['"]([^'"]+)['"]`,
		`\bnew\s+Key\s*\(\s*['"]([^'"]+)['"]`,
	],
	"java": [
		`\.signWith\s*\([^;()]*,\s*"([^"]+)"`,
		`\.setSigningKey\s*\(\s*"([^"]+)"`,
		`\bAlgorithm\.HMAC(?:256|384|512)\s*\(\s*"([^"]+)"`,
		`\bKeys\.hmacShaKeyFor\s*\(\s*"([^"]+)"`,
	],
	"go": [`\.SignedString\s*\(\s*\[\]byte\s*\(\s*"([^"]+)"`],
	"cs": [`\bnew\s+SymmetricSecurityKey\s*\(\s*Encoding\.\w+\.GetBytes\s*\(\s*"([^"]+)"`],
}

# Calls whose key argument is an identifier (group 1).
_ident_sinks := {
	"js": [`\b(?:jwt|jsonwebtoken|JWT)\.(?:sign|verify)\s*\(\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]`],
	"py": [`\bjwt\.(?:encode|decode)\s*\(\s*(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*(?:key\s*=\s*)?([A-Za-z_]\w*)\s*[,)]`],
	"rb": [`\bJWT\.(?:encode|decode)(?:\s*\(\s*|\s+)(?:\{(?:[^{}]|\{[^{}]*\})*\}|[^,{}]+?)\s*,\s*([A-Za-z_]\w*)\s*[,)]`],
	"php": [`\bJWT::(?:encode|decode)\s*\(\s*(?:\[(?:[^\[\]]|\[[^\[\]]*\])*\]|[^,\[\]]+?)\s*,\s*(?:new\s+Key\s*\(\s*)?\$(\w+)\s*[,)]`],
	"java": [
		`\.(?:signWith\s*\([^;()]*,|setSigningKey\s*\()\s*([A-Za-z_]\w*)\s*\)`,
		`\bAlgorithm\.HMAC(?:256|384|512)\s*\(\s*([A-Za-z_]\w*)(?:\.getBytes\s*\([^()]*\))?\s*\)`,
		`\bKeys\.hmacShaKeyFor\s*\(\s*([A-Za-z_]\w*)(?:\.getBytes\s*\([^()]*\))?\s*\)`,
	],
	"go": [`\.SignedString\s*\(\s*([A-Za-z_]\w*)\s*\)`],
	"cs": [`\bnew\s+SymmetricSecurityKey\s*\(\s*Encoding\.\w+\.GetBytes\s*\(\s*([A-Za-z_]\w*)\s*\)`],
}

# Literal anchors: a file (and a line) must carry one before any regex runs.
_anchors := {
	"js": ["jwt", "JWT"],
	"py": ["jwt."],
	"rb": ["JWT."],
	"php": ["JWT::", "new Key"],
	"java": ["signWith", "setSigningKey", "Algorithm.HMAC", "hmacShaKeyFor"],
	"go": ["SignedString"],
	"cs": ["SymmetricSecurityKey"],
}

_anchored(lang, s) if {
	some a in _anchors[lang]
	contains(s, a)
}

_has_jwt(s) if contains(s, "jwt")

_has_jwt(s) if contains(s, "JWT")

_has_jwt(s) if contains(s, "Jwt")

_placeholder(v) if count(v) < 3

_placeholder(v) if regex.match(`(?i)^(?:change[-_ ]?me.*|your[-_ ].*|<.*>|.*\$\{.*|\{\{.*|%\(.*|x{3,}|\*+|todo|tbd|replace[-_ ]?me.*|placeholder|example|none|null|undefined|secret_here|\.\.\.)$`, v)

# The value names a setting or environment variable rather than being one.
_placeholder(v) if regex.match(`^[A-Z][A-Z0-9_]*$`, v)

_placeholder(v) if regex.match(`^\w+:\w+(?::\w+)*$`, v)

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_call_text(lines, i) := concat("\n", [l |
	some j in numbers.range(i, min([count(lines) - 1, i + 5]))
	l := lines[j]
	not helpers.is_comment_line(l)
])

_odd_quotes(p) if count(indexof_n(p, `"`)) % 2 == 1

_odd_quotes(p) if count(indexof_n(p, "'")) % 2 == 1

# ── A literal passed straight to a signing or verification call ─────────

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	res := _lit_sinks[lang]
	_anchored(lang, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_anchored(lang, line)
	not helpers.is_comment_line(line)
	some re in res

	# the call begins on this line, outside a quoted string
	m := regex.find_all_string_submatch_n(concat("", [`^([^\n]*?)(?:`, re, `)`]), _call_text(lines, i), 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	v := m[0][2]
	not _placeholder(v)
	some j in numbers.range(i, min([count(lines) - 1, i + 5]))
	contains(lines[j], v)
	not _earlier(lines, i, j, v)
	f := _finding(path, j, lines[j], "JWT key is a hard-coded string literal; anyone who can read the source can forge tokens. Load it from the environment or a secrets manager")
}

_earlier(lines, i, j, v) if {
	j > i
	some k in numbers.range(i, j - 1)
	contains(lines[k], v)
}

# ── A literal assigned to a variable that is then used as the key ───────

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	res := _ident_sinks[lang]
	_anchored(lang, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_anchored(lang, line)
	not helpers.is_comment_line(line)
	some re in res
	m := regex.find_all_string_submatch_n(concat("", [`^([^\n]*?)(?:`, re, `)`]), _call_text(lines, i), 1)
	count(m) > 0
	not _odd_quotes(m[0][1])
	ident := m[0][2]
	# the literal may be wrapped in []byte(...) or an encoding call
	assign_re := concat("", [`^\s*(?:(?:export|const|let|var|final|static|private|public|protected|internal|val|readonly)\s+)*(?:[\w<>\[\]]+\s+)?\$?`, ident, `\s*:?=\s*(?:\[\]byte\s*\(\s*|TextCodec\.BASE64\.encode\s*\(\s*|Base64\.getEncoder\(\)\.encodeToString\s*\(\s*)?["'\x60]([^"'\x60]+)["'\x60](?:\.getBytes\s*\([^()]*\))?\s*\)?\s*;?\s*$`])
	some j, l in lines
	contains(l, ident)
	am := regex.find_all_string_submatch_n(assign_re, l, 1)
	count(am) > 0
	not _placeholder(am[0][1])
	f := _finding(path, j, l, "A hard-coded string assigned here is used as a JWT signing/verification key; load it from the environment or a secrets manager")
}

# ── A JWT-named setting assigned a literal ───────────────────────────────

_name_re := `(?i)\bjwt[._-]?(?:secret|signing[._-]?key|key)(?:[._-]?key)?\b["']?\]?\s*(?:=>|:?=|:)\s*(?:\[\]byte\s*\(\s*)?["'\x60]([^"'\x60]+)["'\x60]`

_conf_name_re := `(?i)^\s*(?:export\s+)?[\w.-]*\bjwt[._-]?(?:secret|signing[._-]?key|key)(?:[._-]?key)?\s*[:=]\s*["']?([^\s"'#]+)["']?\s*$`

findings contains f if {
	some path, content in input.file_contents
	lang := _lang(path)
	lang != "conf"
	_has_jwt(content)
	regex.match(`(?i)jwt[._-]?(?:secret|signing|key)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_jwt(line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_name_re, line, 1)
	count(m) > 0
	not _placeholder(m[0][1])
	not regex.match(`(?i)\b(?:os\.environ|getenv|process\.env|ENV\[|ENV\.fetch|System\.getenv|Environment\.GetEnvironmentVariable)`, line)
	f := _finding(path, i, line, "JWT secret is hard-coded; load the signing key from the environment or a secrets manager")
}

findings contains f if {
	some path, content in input.file_contents
	_lang(path) == "conf"
	not _template(path)
	_has_jwt(content)
	regex.match(`(?i)jwt[._-]?(?:secret|signing|key)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_jwt(line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_conf_name_re, line, 1)
	count(m) > 0
	not _placeholder(m[0][1])
	f := _finding(path, i, line, "JWT secret committed in configuration; inject it at deploy time from a secrets manager")
}
