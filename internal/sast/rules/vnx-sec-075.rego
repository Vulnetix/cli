package vulnetix.rules.vnx_sec_075

import data.vulnetix.helpers
import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-075",
	"name": "WireGuard private key",
	"description": "Reports a literal WireGuard private or preshared key: a 32-byte key in base64 (43 characters and a closing '=') written as PrivateKey = or PresharedKey = in a wg-quick/INI configuration in any file, and, in a file that mentions WireGuard (wireguard, wg-quick, wgtypes), the same key assigned to a private_key/private-key/preshared_key-style name in YAML, JSON, Nix, HCL, .env or compose environment entries (WIREGUARD_PRIVATE_KEY=...), NetworkManager keyfiles (private-key=), RouterOS scripts (private-key=, quoted) and OpenWrt UCI (option private_key '...'), or passed to wgtypes.ParseKey(). Not reported: PublicKey lines, key references (${WG_PRIVATE_KEY}, wg set ... private-key <file>), values that are not a well-formed 32-byte base64 key (variable names, <placeholders>, AAAA... or xxxx... runs, low-entropy values), key-shaped values under other names in files unrelated to WireGuard, *.example/*.sample/*.template files, Markdown, and test, fixture, vendored and generated files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-075/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "wireguard", "vpn", "credentials"],
}

# A Curve25519 key is 32 bytes: 43 base64 characters, the last of which
# carries only 4 data bits, then one "=" of padding.
_key := `[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=`

# wg-quick / INI form, any file.
_ini := concat("", [`(?i)^\s*(?:PrivateKey|PresharedKey)\s*=\s*(`, _key, `)\s*(?:[#;].*)?$`])

# Key-value form in files that are about WireGuard.
# The separator is ":" or "=" (YAML, JSON, HCL, .env, NetworkManager
# private-key=, RouterOS private-key="..."), or whitespace (OpenWrt UCI:
# option private_key '...').
_kv := concat("", [`(?i)(?:private[_-]?key|preshared[_-]?key|psk)["']?(?:\s*[:=]\s*|\s+)["']?(`, _key, `)(?:["'\s,;]|$)`])

_parse := concat("", [`wgtypes\.ParseKey\(\s*"(`, _key, `)"`])

_doc_suffix := [".md", ".markdown", ".rst", ".adoc", ".example", ".sample", ".template", ".dist", ".tmpl"]

_skip(path) if {
	low := lower(path)
	some s in _doc_suffix
	endswith(low, s)
}

_skip(path) if regex.match(`(?i)\.(example|sample|template)\.[a-z0-9]+$`, path)

# Cheap literal gate before the key-shaped regular expression.
_names := [
	"PrivateKey", "privateKey", "private_key", "PRIVATE_KEY", "privatekey", "Private_Key",
	"PresharedKey", "presharedKey", "preshared_key", "PRESHARED_KEY", "presharedkey",
	"psk", "PSK", "ParseKey", "private-key", "preshared-key",
]

_named(content) if {
	some n in _names
	contains(content, n)
}

_wg_file(content) if regex.match(`(?i)wireguard|wg-quick|wgtypes|\[Interface\]`, content)

_is_wg(content) := true if _wg_file(content)

_is_wg(content) := false if not _wg_file(content)

_ini_keys(line) := {m[1] | some m in regex.find_all_string_submatch_n(_ini, line, 1)}

_wg_keys(line) := {m[1] | some m in regex.find_all_string_submatch_n(_kv, line, -1)} | {m[1] | some m in regex.find_all_string_submatch_n(_parse, line, -1)}

_line_keys(line, true) := _ini_keys(line) | _wg_keys(line)

_line_keys(line, false) := _ini_keys(line)

findings contains finding if {
	some path, content in input.file_contents
	_named(content)
	regex.match(concat("", [`(?i)key["']?\s*[:=(\s]\s*"?["']?`, _key]), content)
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	not _skip(path)
	wg := _is_wg(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)key`, line)
	some tok in _line_keys(line, wg)
	not secrets.is_example_token(tok)
	secrets.high_entropy(tok, 4)
	finding := {
		"rule_id": metadata.id,
		"message": "WireGuard private or preshared key found; generate a new keypair (wg genkey), update every peer, and load the key from a file with restricted permissions or a secrets manager",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, tok, "***"),
	}
}
