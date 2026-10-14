package vulnetix.rules.vnx_node_030

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-030",
	"name": "TURN server allowing reserved IP addresses",
	"description": "Reports a TURN relay that will forward traffic to loopback, private or link-local addresses, which lets any TURN client reach internal services and the cloud metadata endpoint through the relay. Three concrete signals: a node-turn server constructed in JavaScript/TypeScript (new <name>(...) where <name> is bound by require/import of 'node-turn', a library with no peer-address deny list); a coturn configuration (turnserver.conf, coturn.conf) or coturn command-line argument (in YAML manifests or JS) that enables allow-loopback-peers or sets allowed-peer-ip to a loopback/RFC 1918/link-local range; and a turnserver.conf that sets no denied-peer-ip at all (coturn relays to RFC 1918 and link-local peers by default; reported once, on the file's first setting). Not reported: WebRTC client ICE configuration (iceServers), generic IP comparisons in application code, a coturn configuration that denies peer ranges, commented-out settings, and classes merely named Turn.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-030/",
	"languages": ["javascript", "typescript"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-200"],
	"attack_technique": ["T1046"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["webrtc", "turn", "ip-address", "security"],
}

_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".mjs")
_is_js(path) if endswith(path, ".cjs")

_is_coturn_conf(path) if regex.match(`(^|/)[^/]*(turnserver|coturn)[^/]*\.conf$`, path)

_is_yaml(path) if endswith(path, ".yaml")
_is_yaml(path) if endswith(path, ".yml")

_bind_re := `(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]node-turn['"]\s*\)|import\s+([A-Za-z_$][\w$]*)\s+from\s+['"]node-turn['"])`

_private_range_re := `^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.0\.0\.0|::1|f[cd][0-9a-f]{2}:|fe80:)`

_strip(s) := regex.replace(s, concat("", [`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`, "`[^`]*`"]), `''`)

# node-turn server construction
findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	contains(content, "node-turn")
	some m in regex.find_all_string_submatch_n(_bind_re, content, -1)
	name := concat("", [m[1], m[2]])
	lines := split(content, "\n")
	some i, line in lines
	contains(line, name)
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\bnew\s+`, name, `\s*\(`]), _strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "node-turn relays to any peer address, including loopback, private and cloud-metadata addresses; front it with a peer-address deny list or use coturn with denied-peer-ip ranges",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# allow-loopback-peers / allowed-peer-ip=<private> in coturn config or args
_dangerous_setting(line) := "allow-loopback-peers lets the relay reach services on the TURN host itself" if {
	regex.match(`(?:^|[\s"'\-])allow-loopback-peers\b(?:\s*=\s*(?:true|1|yes))?\s*["',]?\s*$`, line)
}

_dangerous_setting(line) := "allowed-peer-ip opens a reserved address range to relaying" if {
	m := regex.find_all_string_submatch_n(`(?:^|[\s"'\-])allowed-peer-ip\s*=\s*([0-9a-fA-F:.]+)`, line, 1)
	count(m) > 0
	regex.match(_private_range_re, lower(m[0][1]))
}

_config_file(path) if _is_coturn_conf(path)
_config_file(path) if _is_yaml(path)
_config_file(path) if _is_js(path)

findings contains finding if {
	some path, content in input.file_contents
	_config_file(path)
	regex.match(`allow-loopback-peers|allowed-peer-ip`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "-peer")
	not helpers.is_comment_line(line)
	not _js_literal_prose(path, line)
	msg := _dangerous_setting(trim_space(line))
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("coturn %s; remove it and deny loopback, RFC 1918 and link-local peers with denied-peer-ip", [msg]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# In JS the flag must be an argument of its own ('--allow-loopback-peers'),
# not a phrase in a longer message string.
_js_literal_prose(path, line) if {
	_is_js(path)
	not regex.match(`['"\x60]--?(?:allow-loopback-peers|allowed-peer-ip=[^'"\x60]*)['"\x60]`, line)
}

# turnserver.conf with no denied-peer-ip at all
findings contains finding if {
	some path, content in input.file_contents
	_is_coturn_conf(path)
	not regex.match(`(?m)^\s*denied-peer-ip\s*=`, content)
	lines := split(content, "\n")
	firsts := [i | some i, l in lines; trim_space(l) != ""; not helpers.is_comment_line(l)]
	count(firsts) > 0
	i := firsts[0]
	finding := {
		"rule_id": metadata.id,
		"message": "coturn configuration sets no denied-peer-ip, so the relay forwards to RFC 1918 and link-local (cloud metadata) addresses; add denied-peer-ip lines for 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16 and IPv6 equivalents",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
