package vulnetix.rules.vnx_sec_074

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-074",
	"name": "Kubernetes Secret manifest with credential data",
	"description": "Reports each credential entry with a literal value in the data: or stringData: block of a committed Kubernetes Secret manifest (a .yaml/.yml document whose top-level kind is Secret, including multi-document files): an entry whose key names a credential (password, token, secret, key, auth, credentials, private, cert key, connection string or URL, .dockerconfigjson) and whose value is a literal, a base64 string in data: or a block scalar. Base64 in data: is encoding, not encryption, so anyone with read access to the repository has the value. Not reported: non-credential entries (host, port, username, database), empty values, Helm and other templated values ({{ }}), envsubst and shell references (${VAR}, $(VAR)), release-pipeline token substitutions (#{Name}#, __NAME__, %%NAME%%), SOPS-encrypted ENC[...] values, <placeholder> and argocd-vault-plugin <path:...> values, default or placeholder words (password, changeme, admin, xxxx), including base64 of them, SealedSecret, ExternalSecret and other kinds, ConfigMap data, secretKeyRef references, and test, fixture and testdata files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-074/",
	"languages": [],
	"severity": "high",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["secrets", "kubernetes", "credentials"],
}

_kind_re := `^kind:\s*["']?Secret["']?\s*(#.*)?$`

_block_re := `^(data|stringData):\s*(#.*)?$`

_entry_re := `^(\s+)["']?([A-Za-z0-9_.-]+)["']?:\s*(.*?)\s*$`

_cred_key_re := `(?i)(pass|pwd|secret|token|key|auth|cred|private|cert|dsn|conn|_url$|^url$|uri$|webhook|cookie|jwt|salt|htpasswd|dockerconfig|dockercfg|\.pem$|\.p12$|\.pfx$|\.jks$)`

_defaults := {
	"password", "passwd", "pass", "pwd", "secret", "changeme", "change_me",
	"root", "admin", "administrator", "test", "testing", "example", "user",
	"username", "guest", "default", "token", "apikey", "api-key", "api_key",
	"mypassword", "password123", "123456", "secretpassword", "mysecretpassword",
	"null", "none", "true", "false",
}

_yaml_suffix(path) if endswith(lower(path), ".yaml")

_yaml_suffix(path) if endswith(lower(path), ".yml")

_unquote(v) := substring(v, 1, count(v) - 2) if regex.match(`^"[^"]*"$|^'[^']*'$`, v)

_unquote(v) := v if not regex.match(`^"[^"]*"$|^'[^']*'$`, v)

_weak(v) if count(v) < 4

_weak(v) if regex.match(`\{\{|\$\{|\$\(|^<.*>$|^\$[A-Za-z_]`, v)

_weak(v) if _defaults[lower(v)]

# SOPS-encrypted values (ENC[AES256_GCM,data:...]) are ciphertext, committed
# by design.
_weak(v) if startswith(v, "ENC[")

# Release-pipeline token substitution: #{Name}# (Azure DevOps replace
# tokens), __NAME__, %%NAME%% and %NAME%.
_weak(v) if regex.match(`^#\{[^}]*\}#$|^__[A-Za-z0-9_.-]+__$|^%%?[A-Za-z0-9_.-]+%%?$`, v)

_weak(v) if secrets.is_placeholder(v)

_weak(v) if regex.match(`(?i)your|placeholder|redacted|changeme`, v)

# data: values are base64; judge what they decode to.
_weak_data(v) if _weak(v)

_weak_data(v) if {
	base64.is_valid(v)
	_weak(trim_space(base64.decode(v)))
}

# The value of a block scalar ("key: |") is its first few content lines.
_value(lines, e, raw) := trim_space(concat(" ", [trim_space(lines[x]) |
	some x in numbers.range(e + 1, min([e + 3, count(lines) - 1]))
])) if {
	regex.match(`^[|>][-+0-9]*$`, raw)
	e + 1 < count(lines)
}

_value(_, _, raw) := _unquote(raw) if not regex.match(`^[|>][-+0-9]*$`, raw)

_weak_entry("data", v) if _weak_data(v)

_weak_entry("stringData", v) if _weak(v)

findings contains finding if {
	some path, content in input.file_contents
	_yaml_suffix(path)
	contains(content, "Secret")
	contains(content, "ata:")
	regex.match(`(?m)^kind:\s*["']?Secret["']?\s*(#.*)?$`, content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	seps := [j | some j, l in lines; startswith(l, "---")]
	some k, kl in lines
	regex.match(_kind_re, kl)
	start := max(array.concat([-1], [j | some j in seps; j < k]))
	stop := min(array.concat([count(lines)], [j | some j in seps; j > k]))
	some h in helpers.span(start + 1, stop - 1)
	hm := regex.find_all_string_submatch_n(_block_re, lines[h], 1)
	count(hm) == 1
	block := hm[0][1]
	h + 1 < stop
	f := _first_entry(lines, h, stop)
	not _left_block(lines, h, f)
	first := regex.find_all_string_submatch_n(_entry_re, lines[f], 1)
	count(first) == 1
	indent := first[0][1]
	some e in numbers.range(h + 1, min([stop - 1, h + 200]))
	em := regex.find_all_string_submatch_n(_entry_re, lines[e], 1)
	count(em) == 1
	em[0][1] == indent

	# still inside the block: no top-level line between the header and here
	not _left_block(lines, h, e)
	regex.match(_cred_key_re, em[0][2])
	v := _value(lines, e, em[0][3])
	v != ""
	not _weak_entry(block, v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Kubernetes Secret commits a literal value for %q in %s; use Sealed Secrets, the External Secrets Operator or SOPS, and rotate the value", [em[0][2], block]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": e + 1,
		"snippet": concat("", [indent, em[0][2], ": ***"]),
	}
}

# The block's first entry: the first indented line that is not blank or a
# comment ("stringData:\n  # rotated quarterly\n  password: ...").
_first_entry(lines, h, stop) := min([f |
	some f in numbers.range(h + 1, min([stop - 1, h + 20]))
	regex.match(`^\s+[^\s#]`, lines[f])
])

_left_block(lines, h, e) if {
	some t in numbers.range(h + 1, e)
	regex.match(`^[^\s#]`, lines[t])
}
