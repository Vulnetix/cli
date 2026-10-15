# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1051

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1051",
	"name": "Initialization with Hard-Coded Network Resource Configuration Data",
	"description": "A literal IPv4 address is written into Python, JavaScript/TypeScript, Java or Go source as the network resource a program initialises against (CWE-1051): a URL or connection string whose host is an IP literal (\"http://10.0.4.12:8080/api\", \"postgresql://app@10.0.4.12/db\"), an IP literal assigned to or passed as a host/address/server/endpoint/broker/proxy name (host=\"10.0.4.12\", DB_HOST = '10.0.4.12', {\"host\": \"10.0.4.12\"}), or an IP literal given directly to a socket or dial API (socket.connect((\"10.0.4.12\", 6379)), net.Dial(\"tcp\", \"10.0.4.12:6379\"), new Socket(\"10.0.4.12\", 80), InetAddress.getByName, net.connect). Compound schemes such as jdbc:mysql:// count as URLs, and a property set by a host-like key counts as a setting (props.put(\"bootstrap.servers\", \"10.0.1.15:9092\"), os.getenv(\"DB_HOST\", \"10.0.0.5\")). Such an address ties the build to one network and must be changed in code when the service moves. Not reported: loopback (127.x), 0.0.0.0, broadcast and the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24, the cloud metadata address 169.254.169.254, CIDR blocks (10.0.0.0/8), hostnames such as localhost or api.example.com (a named endpoint is not tied to one address), dotted version strings and OIDs, addresses given to a parse, validate or compare function (net.ParseIP(\"192.168.1.1\"), remote_addr == \"10.0.0.1\"), comments and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1051/",
	"languages": ["python", "javascript", "typescript", "java", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1051],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["hardcoded-network-config", "cwe-1051"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go"}

_ext_ok(path) if {
	some ext in _exts
	endswith(path, ext)
}

_octet := `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`

# A quoted IPv4 literal (optionally behind a URL scheme and userinfo, optionally
# followed by a port) that ends the host part: the next character is a quote,
# a port, a path or a query, never another dot or a CIDR mask.
_ip_lit := concat("", [`["'\x60](?:[a-zA-Z][a-zA-Z0-9+.\-]*(?::[a-zA-Z][a-zA-Z0-9+.\-]*)*://(?:[^@/"'\s]*@)?)?(`, _octet, `\.`, _octet, `\.`, _octet, `\.`, _octet, `)(?::\d{1,5})?(?:["'\x60?]|/[^\d])`])

_gate := `["'\x60/@]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:"'\x60/?]`

# 1. URL or connection string whose host is the IP literal. The scheme may be
#    compound (jdbc:mysql://, jdbc:postgresql://).
_url_re := concat("", [`["'\x60][a-zA-Z][a-zA-Z0-9+.\-]*(?::[a-zA-Z][a-zA-Z0-9+.\-]*)*://(?:[^@/"'\s]*@)?(`, _octet, `(?:\.`, _octet, `){3})(?::\d{1,5})?(?:["'\x60/?])`])

# 2. Host-like name assigned or passed the literal (kwarg, assignment, map key,
#    struct field, builder call such as setHost("...")).
_named_re := concat("", [`([A-Za-z_]\w*)["'\x60]?\s*(?::=|[:=]|\()\s*(?:[\[{]\s*)?`, _ip_lit])

_hosty(key) if regex.match(`(?i)host|addr|server|endpoint|broker|proxy|bind|upstream|remote|dsn|url|uri|gateway|peer`, key)

_hosty(key) if regex.match(`(?:^|_)(?i:ip)(?:_|s?$|[A-Z])|[a-z](?:IP|Ip)(?:[A-Z_]|s?$)`, key)

_named(line) if {
	some m in regex.find_all_string_submatch_n(_named_re, line, -1)
	_hosty(m[1])
	not _parser_name(m[1])
}

# A property set by key: props.put("bootstrap.servers", "10.0.1.15:9092"),
# setProperty("db.host", ...), os.getenv("DB_HOST", "10.0.0.5").
_kv_re := concat("", [`["']([\w.\-]+)["']\s*,\s*`, _ip_lit])

_named(line) if {
	some m in regex.find_all_string_submatch_n(_kv_re, line, -1)
	_hosty(m[1])
}

# Functions that parse, validate or compare an address rather than connect to
# it (net.ParseIP("192.168.1.1"), isPrivateIp("10.0.0.1")).
_parser_name(name) if regex.match(`^(?i:parse|is|valid|check|match|contains|equal|compare|lookup_?net|in_?range)`, name)

# 3. The literal handed to a socket or dial API.
_api_re := concat("", [`(?:\.(?:connect|create_connection|bind|sendto|connect_ex)\s*\(\s*\(\s*|\bnet\.Dial(?:Timeout)?\s*\(\s*"[a-z0-9]+"\s*,\s*|\bnew\s+(?:Socket|InetSocketAddress)\s*\(\s*|InetAddress\.getByName\s*\(\s*|\bnet\.(?:connect|createConnection)\s*\(\s*\d+\s*,\s*)`, _ip_lit])

_shape(line) if regex.match(_url_re, line)

_shape(line) if _named(line)

_shape(line) if regex.match(_api_re, line)

# Addresses that are not configuration of a real network resource.
_excluded_ip(ip) if startswith(ip, "127.")

_excluded_ip(ip) if startswith(ip, "0.")

_excluded_ip(ip) if startswith(ip, "255.")

_excluded_ip(ip) if startswith(ip, "192.0.2.")

_excluded_ip(ip) if startswith(ip, "198.51.100.")

_excluded_ip(ip) if startswith(ip, "203.0.113.")

_excluded_ip("169.254.169.254")

_ips(line) := {m[1] |
	some m in regex.find_all_string_submatch_n(_ip_lit, line, -1)
}

findings contains finding if {
	some path, content in input.file_contents
	_ext_ok(path)
	not helpers.is_test_path(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	_shape(line)
	ips := sort([ip | some ip in _ips(line); not _excluded_ip(ip)])
	count(ips) > 0
	ip := ips[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Network resource initialised with the hard-coded address %s; read the host from configuration or service discovery (CWE-1051)", [ip]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
