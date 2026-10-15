# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_350

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-350",
	"name": "Reliance on Reverse DNS Resolution for a Security-Critical Action",
	"description": "An access decision is made on the host name a reverse DNS lookup returned for the peer's address. The PTR record belongs to whoever controls the address block, so an attacker names their own IP 'gw.example.com' and passes a suffix or allowlist check. Reported: a reverse lookup (Python socket.gethostbyaddr/getnameinfo, socket.getfqdn(address) and dnspython resolve_address; Java request.getRemoteHost(), InetAddress getCanonicalHostName()/getHostName(); Go net.LookupAddr and Resolver.LookupAddr; Node dns.reverse/dns.promises.reverse/resolver.reverse; PHP gethostbyaddr() and $_SERVER['REMOTE_HOST']; Ruby Resolv.getname(s)/getnameinfo) whose result is compared, on the same line or within the next eight lines (directly, through a loop variable or a callback parameter), by endsWith/HasSuffix/startsWith/equals/==/!=/in/includes/contains/preg_match/=~. getHostName() counts only in files that use InetAddress/InetSocketAddress, since Apache HttpHost.getHostName() resolves nothing. Not reported: getnameinfo() with NI_NUMERICHOST, forward-confirmed lookups (a gethostbyname/getaddrinfo/LookupHost/LookupIP/getAllByName/dns.lookup/resolve within the window, as for verifying Googlebot), results that are only logged or displayed, null/empty checks, the local host name (getLocalHost(), getfqdn() with no argument), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-350/",
	"languages": ["go", "java", "node", "php", "python", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [350],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["host-validation", "cwe-350"],
}

_exts := {".py", ".java", ".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".rb"}

_gate_words := {"gethostbyaddr", "getfqdn(", "getnameinfo", "resolve_address", "getRemoteHost", "getCanonicalHostName", "getHostName", "LookupAddr", ".reverse(", "REMOTE_HOST", "Resolv.getname"}

_reverse_re := `\bgethostbyaddr\s*\(|\bgetfqdn\(\s*[^)\s]|\bgetnameinfo\s*\(|\.resolve_address\(|\bgetRemoteHost\(\)|\.getCanonicalHostName\(\)|\.getHostName\(\)|\bLookupAddr\(|\b(?:dns(?:\.promises)?|dnsPromises|resolver)\.reverse\(|\$_SERVER\[\s*["']REMOTE_HOST["']\s*\]|\bResolv\.getnames?\(`

_forward_re := `\bgethostbyname(?:_ex|l)?\s*\(|\bgetaddrinfo\s*\(|\bLookup(?:Host|IP|IPAddr|NetIP)\(|\bgetAllByName\(|\bgetByName\(\s*(?:host|name|hostname|canonical)\w*\s*\)|\b(?:dns(?:\.promises)?|dnsPromises|resolver)\.(?:lookup|resolve4?|resolve6)\(|\bResolv\.getaddress(?:es)?\(|\bdns_get_record\s*\(|\.resolve\(\s*(?:host|name)\w*\s*,\s*["'](?:A|AAAA)["']`

_compare_re := `\.(?:endsWith|endswith|startsWith|startswith|equals|equalsIgnoreCase|includes|contains|matches|match|test)\(|\.(?:end_with|start_with|include)\?|\bstrings\.(?:HasSuffix|HasPrefix|EqualFold|Contains)\(|[=!]==?|\bin\s+[A-Za-z_]|\bpreg_match\s*\(|\bin_array\s*\(|=~|\bstr_(?:ends|starts)_with\s*\(|\bfnmatch\s*\(`

# Comparisons that only test for absence decide nothing about the name.
_strip_null(s) := regex.replace(s, `[=!]==?\s*(?:""|''|nil|null|None|undefined)\b|\b(?:nil|null|None|undefined)\s*[=!]==?|[=!]=\s*nil\b`, " ")

_names(line) := ({v | v := helpers.assigned_first(line)} | {concat("", [m[1], m[2]]) |
	some m in regex.find_all_string_submatch_n(`(?:const|let|var)\s*\[\s*([A-Za-z_]\w*)|^\s*\$([A-Za-z_]\w*)\s*=[^=]`, line, -1)
}) | {m[1] |
	some m in regex.find_all_string_submatch_n(`(?:\(\s*\w+\s*,|function\s*\w*\s*\(\s*\w+\s*,)\s*([A-Za-z_]\w*)\s*\)`, line, -1)
}

_gated(content) if {
	some w in _gate_words
	contains(content, w)
}

_in_string(line, tok) if {
	prefix := substring(line, 0, indexof(line, tok))
	some q in {"\"", "'", "`"}
	strings.count(prefix, q) % 2 == 1
}

# The line itself decides on the looked-up name.
_decides(lines, i, names) if regex.match(_compare_re, _strip_null(lines[i]))

# A later line references the name (or a loop/lambda over it) and compares.
_decides(lines, i, names) if {
	some v in names
	end := min([count(lines) - 1, i + 8])
	end > i
	some k in numbers.range(i + 1, end)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\b`, v, `\b`]), l)
	text := _strip_null(concat("\n", array.slice(lines, k, min([count(lines), k + 3]))))
	regex.match(_compare_re, text)
}

# getHostName() is a reverse lookup only on java.net.InetAddress /
# InetSocketAddress; Apache HttpHost.getHostName() returns the configured name.
_not_a_lookup(".getHostName()", _, content) if not contains(content, "Inet")

# getnameinfo with NI_NUMERICHOST formats the address and resolves nothing.
_not_a_lookup(tok, line, _) if {
	startswith(tok, "getnameinfo")
	contains(line, "NI_NUMERICHOST")
}

findings contains finding if {
	some path, content in input.file_contents
	some e in _exts
	endswith(path, e)
	_gated(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_reverse_re, line)
	not helpers.is_comment_line(line)
	not contains(line, "getLocalHost()")
	tok := regex.find_n(_reverse_re, line, 1)[0]
	not _in_string(line, tok)
	not _not_a_lookup(tok, line, content)
	_decides(lines, i, _names(line))
	not regex.match(_forward_re, helpers.code_window(lines, i, 3, 10))
	finding := {
		"rule_id": metadata.id,
		"message": "An access decision relies on the host name from a reverse DNS lookup, which the owner of the peer's address controls. Decide on the address, or forward-confirm the name (resolve it and check the peer's address is among the results)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
