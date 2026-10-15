package vulnetix.rules.vnx_sec_072

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-072",
	"name": "Generic high-entropy API key / secret",
	"description": "Reports a literal credential assigned to a name that ends in a credential word (api_key/apiKey/api-key, secret, secret_key, client_secret, token, access_token, auth_token, password, passwd, credential(s), creds, private_key, access_key): an assignment, constant, object or JSON key, keyword argument, typed declaration (Go string, TypeScript : string, Kotlin/Swift : String, Rust : &str) or XML setting (<add key=\"PaymentApiKey\" value=\"...\"/>, Android <string name=\"maps_api_key\">) whose quoted value (or unquoted value in .env, YAML, .properties, .ini, .conf and .cfg files) is at least 20 token characters, mixes letters and digits, and has Shannon entropy of at least 3.5. The value is masked in the snippet. Not reported: values read from the environment or configuration, names that only contain a credential word (TOKEN_URL, passwordField, secretName, tokenizer, nextPageToken, authenticationMethod), comparisons (==, ===), placeholder and low-entropy values (YOUR_API_KEY..., 0000..., xxxx..., changeme, words such as AuthKeyOfDoomThat...), dotted identifiers and lowercase word-lists, subresource-integrity hashes (sha256-...), lowercase secret-store paths (projects/p/secrets/db-password/versions/3), comment lines, Markdown/reStructuredText/AsciiDoc/text, HTML and *.example/*.sample files, examples/samples/demo/docs directories, and test, fixture, vendored and generated files. Provider-specific secret rules, VNX-259 (hard-coded passwords) and VNX-BASH-005 (shell scripts) report some of the same lines.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-072/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "generic", "high-entropy", "credentials"],
}

_doc_suffix := [
	".md", ".markdown", ".rst", ".adoc", ".txt", ".html", ".htm", ".svg",
	".example", ".sample", ".template", ".dist", ".tmpl",
]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

# Kotlin/Gradle multiplatform test source sets (src/jvmTest/, src/androidTest/).
_skip(path) if regex.match(`(^|/)src/[A-Za-z]*[Tt]est[A-Za-z]*/`, path)

_skip(path) if regex.match(`(?i)(^|/)(examples?|samples?|demos?|docs?|documentation)/`, path)

_skip(path) if regex.match(`(?i)\.(example|sample|template)\.[a-z0-9]+$`, path)

# The name must END in a credential word.
_word := `(?:api[_-]?key|apikey|secret(?:[_-]?key)?|token|password|passwd|credentials?|creds|private[_-]?key|access[_-]?key)`

# The name, an optional type (Go "string", TypeScript ": string", Kotlin/Swift
# ": String", Rust ": &str" / ": &'static str"), then the assignment.
_name := concat("", [`(?i)`, _word, `['"]?(?:\s+string|\s*:\s*(?:&(?:'static\s+)?str|String|string))?\s*(?::=|=>|=|:)\s*`])

_quoted := concat("", [_name, `['"\x60]([A-Za-z0-9+/=_.~-]{20,})['"\x60]`])

# XML settings: <add key="PaymentApiKey" value="..."/> (.NET) and
# <string name="maps_api_key">...</string> (Android resources).
_xml_add := concat("", [`(?i)\bkey="[A-Za-z0-9_.:-]*`, _word, `"\s+value="([A-Za-z0-9+/=_.~-]{20,})"`])

_xml_string := concat("", [`(?i)\bname="[A-Za-z0-9_.:-]*`, _word, `">([A-Za-z0-9+/=_.~-]{20,})</`])

_xml_patterns := [_xml_add, _xml_string]

_xml_file(path) if regex.match(`(?i)\.(xml|config)$`, path)

_bare := concat("", [_name, `([A-Za-z0-9+/=_.~-]{20,})\s*$`])

_config_suffix := [".yml", ".yaml", ".properties", ".ini", ".conf", ".cfg", ".env"]

_config_file(path) if {
	low := lower(path)
	some s in _config_suffix
	endswith(low, s)
}

_config_file(path) if regex.match(`(^|/)\.env(\.[A-Za-z0-9_-]+)?$`, path)

_weak(v) if secrets.is_example_token(v)

_weak(v) if regex.match(`(?i)your|replace|placeholder|example|changeme|redacted|dummy|sample|todo|insert`, v)

_weak(v) if not regex.match(`[0-9]`, v)

_weak(v) if not regex.match(`[A-Za-z]`, v)

_weak(v) if not secrets.high_entropy(v, 3.5)

# Subresource-integrity hashes and dotted identifiers.
_weak(v) if regex.match(`^sha(256|384|512)-`, v)

_weak(v) if regex.match(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`, v)

# A lowercase list of words (model names, field names, slugs).
_weak(v) if regex.match(`^[a-z0-9]+([-_.][a-z0-9]+){2,}$`, v)

# A lowercase resource path (projects/p/secrets/name/versions/3,
# secret/data/app/token): it names a secret in a store, it is not one.
_weak(v) if regex.match(`^[a-z0-9_.-]+(/[a-z0-9_.-]+){2,}$`, v)

_values(path, line) := {m[1] |
	some m in regex.find_all_string_submatch_n(_quoted, line, -1)
	not _weak(m[1])
}

_bare_values(path, line) := {m[1] |
	_config_file(path)
	some m in regex.find_all_string_submatch_n(_bare, line, -1)
	not _weak(m[1])
}

_xml_values(path, line) := {m[1] |
	_xml_file(path)
	some p in _xml_patterns
	some m in regex.find_all_string_submatch_n(p, line, -1)
	not _weak(m[1])
}

# Cheap gate: a credential word, the rest of the name, then an assignment.
_gate := `(?i)(?:key|secret|token|passw|cred)[a-z0-9_-]*(?:['"]?(?:\s+string)?\s*[:=]|">)`

_keywords := ["key", "secret", "token", "passw", "cred"]

# Candidate values found in the whole file at once: iterating every line of
# every file that mentions "key" or "token" costs seconds on a real tree, so
# the file is split only when it holds a non-placeholder candidate.
_file_candidates(path, content) := {m[1] |
	some m in regex.find_all_string_submatch_n(concat("", ["(?m)", _quoted]), content, -1)
	not _weak(m[1])
} | {m[1] |
	_config_file(path)
	some m in regex.find_all_string_submatch_n(concat("", ["(?m)", _bare]), content, -1)
	not _weak(m[1])
} | {m[1] |
	_xml_file(path)
	some p in _xml_patterns
	some m in regex.find_all_string_submatch_n(p, content, -1)
	not _weak(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	secrets.has_keyword(content, _keywords)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	cands := _file_candidates(path, content)
	count(cands) > 0
	lines := split(content, "\n")
	some i, line in lines
	some c in cands
	contains(line, c)
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	some v in (_values(path, line) | _bare_values(path, line)) | _xml_values(path, line)
	finding := {
		"rule_id": metadata.id,
		"message": "High-entropy literal assigned to a credential name; if it is a real secret, rotate it and load it from the environment or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, v, "***"),
	}
}
