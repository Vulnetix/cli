package vulnetix.rules.vnx_docker_003

import rego.v1

metadata := {
	"id": "VNX-DOCKER-003",
	"name": "Secret in Dockerfile ARG or ENV",
	"description": "An ARG or ENV instruction carries a credential, which ends up in the image config (ENV, visible to docker inspect and every process in the container) or in the build history (ARG values are recorded by the RUN steps that see them). The variable name must say it is a credential: PASSWORD, PASSWD, PASSPHRASE, SECRET, TOKEN, APIKEY, CREDENTIAL(S) or PRIVATEKEY (also as a suffix, as in DBPASSWORD or githubToken), a PASS/PW/_PWD word, or a name ending in _KEY. Reported: ENV with a literal value (KEY=value, the legacy KEY value form, several pairs on one line and pairs on continuation lines), ENV that copies a value into the image from a build arg declared in the same Dockerfile (ARG TOKEN ... ENV TOKEN=${TOKEN}), ENV whose ${VAR:-default} fallback is a literal credential, any credential-named ARG, with or without a default, and, whatever the variable is called, an ENV or ARG value that embeds a password in a URL (postgres://user:password@host). Not reported: names that only point at a secret or describe one (*_FILE, *_PATH, *_URL, *_NAME, *_ID, *_TTL, *_LENGTH, *_ENABLED and similar), public material (GPG_KEY, PUBLIC_*), lookalikes (TOKENIZERS_PARALLELISM, KEYCLOAK_VERSION, MONKEY, PWD), ENV values that are empty, booleans, short numbers, file paths, URLs with no password or a ${VAR} password, a reference to a variable that is not a build arg of the file (ENV X=${X:-}), or placeholders (<...>, your-...-here, xxxx, REPLACE_ME, changeme, {{ templating }}), BuildKit secret mounts (RUN --mount=type=secret), and ARG/ENV text in comments, RUN commands, labels or files that only mention Dockerfiles. Known credential formats in any file are the separate generated secret rules' concern.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-003/",
	"languages": ["docker"],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["docker", "secrets", "credentials", "container"],
}

# ── Dockerfile detection ────────────────────────────────────────────────
_base(path) := lower(b) if {
	parts := split(path, "/")
	b := parts[count(parts) - 1]
}

# cheap substring test first: most paths are not Dockerfiles
_df_word(path) if contains(path, "ockerfile")

_df_word(path) if contains(path, "ontainerfile")

_df_word(path) if contains(path, "OCKERFILE")

_df_word(path) if contains(path, "ONTAINERFILE")

_is_dockerfile(path) if {
	_df_word(path)
	b := _base(path)
	regex.match(`^(dockerfile|containerfile)([._-][a-z0-9_.-]*)?$|[._-](dockerfile|containerfile)$`, b)
	not regex.match(`\.(go|py|pyc|js|mjs|cjs|ts|tsx|jsx|rs|java|kt|kts|rb|php|cs|c|h|cc|cpp|hpp|swift|scala|json|ya?ml|toml|ini|cfg|md|rst|txt|sh|bash|ps1|bat|dockerignore|bak|orig|rej|lock|xml|html?|tf|hcl|rego|snap|golden|diff|patch|log)$`, b)
}

# ── Instruction structure ───────────────────────────────────────────────
_continued(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
}

_in_heredoc(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 60]), i - 1)
	contains(lines[j], "<<")
	some m in regex.find_all_string_submatch_n(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`, lines[j], -1)
	not _heredoc_closed(lines, j, i, m[1])
}

_heredoc_closed(lines, j, i, delim) if {
	some k in numbers.range(j + 1, i)
	trim_space(lines[k]) == delim
}

_not_in_heredoc(_, _, false) := true

_not_in_heredoc(lines, i, true) if not _in_heredoc(lines, i)

# the line that starts the instruction line i belongs to
_start(lines, i) := s if {
	cands := [j | some j in numbers.range(max([0, i - 20]), i); not _continued(lines, j)]
	count(cands) > 0
	s := max(cands)
}

_kw_re := `(?i)^\s*(ARG|ENV)\s+`

# keyword and the text of line i that holds NAME=value pairs
_part(lines, i, hd) := [upper(m[0][1]), text, _same(s, i)] if {
	s := _start(lines, i)
	m := regex.find_all_string_submatch_n(_kw_re, lines[s], 1)
	count(m) > 0
	_not_in_heredoc(lines, s, hd)
	raw := _rest(lines, i, s)
	text := regex.replace(raw, `\\\s*$`, "")
}

_same(a, b) := true if a == b

_same(a, b) := false if a != b

_rest(lines, i, s) := regex.replace(lines[i], _kw_re, "") if s == i

_rest(lines, i, s) := lines[i] if {
	s != i
	not startswith(trim_space(lines[i]), "#")
}

_pair_re := `(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"']*)`

# [name, value] pairs written NAME=value
_eq_pairs(text) := [[m[1], _strip(m[2])] | some m in regex.find_all_string_submatch_n(_pair_re, text, -1)]

# ENV NAME value (the legacy one-variable form)
_legacy_pair(text) := [m[0][1], _strip(m[0][2])] if {
	not regex.match(`^\s*[A-Za-z_][A-Za-z0-9_]*=`, text)
	m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(\S.*?)\s*$`, text, 1)
	count(m) > 0
}

# ARG NAME with no default
_bare_args(text) := [m[1] | some m in regex.find_all_string_submatch_n(`(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)(?:\s|$)`, text, -1)]

_strip(s) := trim(s, "\"'")

# ── Names ───────────────────────────────────────────────────────────────
_secret_name(n) if {
	u := upper(n)
	_secret_word(u)
	not _benign_name(u)
}

_secret_word(u) if regex.match(`(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|APIKEY|CREDENTIALS?|PRIVATEKEY)(_|$)`, u)

_secret_word(u) if regex.match(`(^|_)(PASS|PW)(_|$)`, u)

_secret_word(u) if regex.match(`.+_PWD(_|$)`, u)

_secret_word(u) if {
	regex.match(`(^|_)KEYS?$`, u)
	not regex.match(`(^|_)(GPG|PGP|GNUPG|PUBLIC|PUB|APT|REPO|SORT|PARTITION|CACHE|ROUTING|PRIMARY|FOREIGN|HOST|IDEMPOTENCY|LOOKUP|MAP|REGISTRY|CONFIG)_KEYS?$`, u)
	u != "KEY"
}

# names that point at, size or describe a secret rather than hold one
_benign_name(u) if regex.match(`_(FILE|FILES|PATH|DIR|DIRECTORY|LOCATION|URL|URI|ENDPOINT|HOST|HOSTNAME|PORT|NAME|ID|IDS|ARN|LENGTH|LEN|MIN|MAX|TTL|EXPIRY|EXPIRES|EXPIRATION|LIFETIME|TIMEOUT|ENABLED|ENABLE|DISABLED|DISABLE|REQUIRED|TYPE|MODE|ALGORITHM|ALGO|ALG|SIZE|BITS|VERSION|HEADER|PREFIX|SUFFIX|FORMAT|SOURCE|PROVIDER|STORE|BACKEND|ROTATION|REF|FIELD|PARAM|COUNT|LIMIT|POLICY|SCOPE|SCOPES|ISSUER|AUDIENCE|METHOD|STRATEGY|REGION|MOUNT|USER|USERNAME|EMAIL|KEYRING|KIND|COMMAND|CMD|SCRIPT|HELPER)$`, u)

_benign_name(u) if regex.match(`(^|_)PUBLIC(_|$)`, u)

# ── Values ──────────────────────────────────────────────────────────────
_var_only(v) if regex.match(`^\$\{?[A-Za-z_][A-Za-z0-9_]*(?::?[-=?+][^}]*)?\}?$`, v)

# values that are not a credential: flags, sizes, paths, plain URLs
_harmless(v) if regex.match(`(?i)^(true|false|yes|no|on|off|none|null|nil|enabled?|disabled?)$`, v)

_harmless(v) if regex.match(`^\d{1,6}$`, v)

_harmless(v) if regex.match(`^(~|\.{1,2})?/`, v)

_harmless(v) if regex.match(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/`, v)

_harmless(v) if regex.match(`^[A-Za-z][A-Za-z0-9+.-]*://[^@\s]*$`, v)

_placeholder(v) if v == ""

_placeholder(v) if regex.match(`(?i)^(<.*>|\{\{.*|\[.*\]|x{4,}|\*{3,}|\.{3,}|your[-_ ].*|.*[-_]here|replace[-_]?me|change[-_]?me([-_].+)?|placeholder|dummy|redacted|todo|tbd|unset|n/?a)$`, v)

_literal(v) if {
	not _var_only(v)
	not _harmless(v)
	not _placeholder(v)
}

# ── Snippet: never re-print the credential ──────────────────────────────
_redact(line) := out if {
	a := regex.replace(line, `=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'\\]+)`, "=***")
	out := regex.replace(a, `(?i)^(\s*ENV\s+[A-Za-z_][A-Za-z0-9_]*\s+)[^=\s].*$`, "${1}***")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": _redact(line),
}

# cheap per-line prefilter before any instruction parsing
_cand_re := `(?i)(PASS|PW|SECRET|TOKEN|KEY|CREDENTIAL)`

# ENV with a literal credential
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*ENV\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(_cand_re, line)
	p := _part(lines, i, hd)
	p[0] == "ENV"
	some pair in _env_pairs(p)
	_secret_name(pair[0])
	_literal(pair[1])
	finding := _finding(path, i, line,sprintf("ENV %s holds a hard-coded credential: it is stored in the image config and readable with docker inspect by anyone who can pull the image. Supply it at run time (an orchestrator secret or a mounted file such as %s_FILE) instead", [pair[0], pair[0]]))
}

# ENV that copies a build arg into the image environment
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*ENV\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(_cand_re, line)
	p := _part(lines, i, hd)
	p[0] == "ENV"
	some pair in _env_pairs(p)
	_secret_name(pair[0])
	_var_only(pair[1])
	not _literal_default(pair[1])
	_declared_arg(content, _var_name(pair[1]))
	finding := _finding(path, i, line,sprintf("ENV %s copies a credential into the image environment, where it persists in the image config of every container started from it. Use a BuildKit secret mount (RUN --mount=type=secret) for build-time use and inject it at run time otherwise", [pair[0]]))
}

# ENV TOKEN=${TOKEN:-literal}: the literal is baked in whenever the arg is unset
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*ENV\s`, content)
	contains(content, ":-")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	contains(line, ":-")
	regex.match(_cand_re, line)
	p := _part(lines, i, hd)
	p[0] == "ENV"
	some pair in _env_pairs(p)
	_secret_name(pair[0])
	_literal_default(pair[1])
	finding := _finding(path, i, line,sprintf("ENV %s falls back to a hard-coded credential (${...:-value}): unless the value is supplied, the default is stored in the image config and readable with docker inspect. Supply it at run time instead", [pair[0]]))
}

# a password embedded in a URL (scheme://user:password@host), whatever the name
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*(ENV|ARG)\s.*://[^\s:/@]*:[^\s@/]+@`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	contains(line, "@")
	contains(line, "://")
	p := _part(lines, i, hd)
	some pair in _url_pairs(p)
	_url_password(pair[1])
	finding := _finding(path, i, _redact_url(line), sprintf("%s %s embeds a password in a URL (scheme://user:password@host): it is stored in the Dockerfile and, for ENV, in the image config readable with docker inspect. Pass the URL or the password at run time instead", [p[0], pair[0]]))
}

_url_pairs(p) := _env_pairs(p) if p[0] == "ENV"

_url_pairs(p) := _eq_pairs(p[1]) if p[0] == "ARG"

_url_password(v) if {
	m := regex.find_all_string_submatch_n(`(?i)^[a-z][a-z0-9+.-]*://[^\s:/@]*:([^\s@/]+)@`, v, 1)
	count(m) > 0
	pw := m[0][1]
	not contains(pw, "$")
	not _placeholder(pw)
	not regex.match(`(?i)^(password|pass|pwd|secret|changeme)$`, pw)
}

_redact_url(line) := regex.replace(_redact(line), `(://[^\s:/@]*:)[^\s@/]+@`, "${1}***@")

_var_name(v) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)`, v, 1)
	count(m) > 0
}

# the variable is a build arg of this Dockerfile (otherwise it is empty, or
# whatever an earlier ENV set, and nothing is copied from the build)
_declared_arg(content, n) if regex.match(concat("", [`(?im)^\s*ARG\s+(?:[A-Za-z_][A-Za-z0-9_]*(?:=\S*)?\s+)*`, n, `(\s|=|$)`]), content)

_literal_default(v) if {
	m := regex.find_all_string_submatch_n(`^\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]+)\}$`, v, 1)
	count(m) > 0
	_literal(_strip(m[0][1]))
}

_env_pairs(p) := _eq_pairs(p[1]) if not _legacy(p)

_env_pairs(p) := [_legacy_pair(p[1])] if _legacy(p)

_legacy(p) if {
	p[2]
	_legacy_pair(p[1])
}

# ARG with a hard-coded default
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*ARG\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(_cand_re, line)
	p := _part(lines, i, hd)
	p[0] == "ARG"
	some pair in _eq_pairs(p[1])
	_secret_name(pair[0])
	_literal(pair[1])
	finding := _finding(path, i, line,sprintf("ARG %s has a hard-coded credential as its default: it is in the Dockerfile and in the build history of every RUN step that sees it. Use a BuildKit secret mount (RUN --mount=type=secret,id=...) instead of a build argument", [pair[0]]))
}

# ARG used to pass a credential at build time
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	regex.match(`(?im)^\s*ARG\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(_cand_re, line)
	p := _part(lines, i, hd)
	p[0] == "ARG"
	some n in _build_arg_names(p[1])
	_secret_name(n)
	finding := _finding(path, i, line,sprintf("ARG %s passes a credential as a build argument: build-arg values are recorded in the image history of the RUN steps that use them (docker history). Use a BuildKit secret mount (RUN --mount=type=secret,id=...) instead", [n]))
}

_build_arg_names(text) := {n |
	some n in _bare_args(text)
} | {pair[0] |
	some pair in _eq_pairs(text)
	_unset_default(pair[1])
}

_unset_default(v) if _var_only(v)

_unset_default(v) if _placeholder(v)
