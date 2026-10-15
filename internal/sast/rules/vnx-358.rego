# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_358

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-358",
	"name": "Hand-rolled TLS host name or certificate identity check uses a partial string match",
	"description": "TLS server identity (RFC 6125) is checked by hand with a prefix, suffix or substring test, so a certificate or host the standard would reject passes: evilacme.com ends with acme.com, api.attacker.net starts with api., and any CA will issue a certificate whose subject contains CN=api.acme.com somewhere. Reported in Java: a HostnameVerifier verify(String host, SSLSession s) method or a (host, session) -> lambda passed to setHostnameVerifier/setDefaultHostnameVerifier/hostnameVerifier (its body on the same line or, when the arrow ends the line, the next two) (annotated parameters such as @NonNull included) that tests the host, also after toLowerCase()/trim(), with endsWith/startsWith/contains/indexOf/matches, or tests a certificate name with endsWith/startsWith(host), and does not delegate to another verifier's verify(); a certificate subject or issuer name (getSubjectDN/getSubjectX500Principal/getIssuerDN/getIssuerX500Principal .getName()), inline, through a variable assigned within six lines, or through an X500Principal variable whose getName() is assigned, tested with contains/startsWith/endsWith/indexOf/matches. In Python: a function named like verify_hostname/match_host/check_server_hostname whose host-name parameter (also after .lower()) is tested with endswith/startswith/find, as the right side of `x in host`, or as the argument of a certificate name's endswith/startswith (san.endswith(hostname)), where the function handles a certificate, socket or SSL object (so HTTP Host-header validation is not judged) and the parameter is not a collection of hosts (allowed_hosts, domains), unless the function also calls ssl.match_hostname or another verify routine. Not reported: exact comparisons (equals, ==, membership of the host in an allowlist), a suffix test combined with a delegated verify() call, string tests on ordinary paths and names, test files, comments and string literals. A verifier that returns true for everything is VNX-JAVA-006, and disabled verification is VNX-CRYPTO-005.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-358/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [358],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["improper-standard-check", "tls", "hostname-verification", "cwe-358"],
}

_partial := `\s*\.\s*(?:endsWith|startsWith|contains|indexOf|matches|regionMatches)\s*\(`

_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_indent(line) := count(line) - count(trim_left(line, " \t"))

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_host_msg := "TLS host name is checked with a prefix/suffix/substring test, so look-alike hosts pass (evilacme.com ends with acme.com) and the certificate itself is not matched. Delegate to the default HostnameVerifier / ssl.match_hostname and compare exact names"

_dn_msg := "Certificate subject/issuer name is checked with a substring test: any CA-issued certificate whose name merely contains the string passes. Pin the public key or compare the exact parsed name"

# Body of a block that opens on line i: following lines up to the first
# line (within `span`) indented no deeper than line i and starting with "}"
# (Java) or any code (Python).
_body_end(lines, i, span, closer) := e if {
	end := min([count(lines) - 1, i + span])
	ind := _indent(lines[i])
	stops := [k |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		_indent(lines[k]) <= ind
		regex.match(closer, lines[k])
	]
	e := _first_or(stops, end)
}

_first_or(arr, _) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

# ── Java: HostnameVerifier.verify method ────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "SSLSession")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "verify")
	m := regex.find_all_string_submatch_n(`\bboolean\s+verify\s*\(\s*(?:@[\w.]+\s+)*(?:final\s+)?(?:@[\w.]+\s+)*String\s+(\w+)\s*,\s*(?:@[\w.]+\s+)*(?:final\s+)?(?:@[\w.]+\s+)*[\w.]*SSLSession\s+\w+\s*\)`, line, 1)
	count(m) > 0
	host := m[0][1]
	e := _body_end(lines, i, 20, `^\s*\}`)
	body := concat("\n", array.slice(lines, i + 1, e))
	not regex.match(`\.verify\s*\(`, _strip(body))
	some j in numbers.range(i + 1, e - 1)
	l := lines[j]
	not helpers.is_comment_line(l)
	_java_host_partial(host, _strip(l))
	finding := _finding(path, j, l, _host_msg)
}

# ── Java: (host, session) -> lambda verifier ────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ostnameVerifier")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ostnameVerifier")
	not helpers.is_comment_line(line)
	code := _strip(line)
	m := regex.find_all_string_submatch_n(`(?:[sS]etDefaultHostnameVerifier|[sS]etHostnameVerifier|\.hostnameVerifier|HostnameVerifier\s+\w+\s*=)\s*\(?\s*\(\s*(?:final\s+)?(?:String\s+)?(\w+)\s*,[^)]*\)\s*->\s*(.*)$`, code, 1)
	count(m) > 0
	host := m[0][1]
	rest := _lambda_rest(lines, i, m[0][2])
	_java_host_partial(host, rest)
	not regex.match(`\.verify\s*\(`, rest)
	finding := _finding(path, i, line, _host_msg)
}

# The lambda body; when the arrow ends the line, the next two lines.
_lambda_rest(_, _, r) := r if trim_space(r) != ""

_lambda_rest(lines, i, r) := concat(" ", [_strip(l) | some l in array.slice(lines, i + 1, i + 3)]) if trim_space(r) == ""

# ── Java: certificate DN tested by substring ────────────────────────────
_dn_src := `get(?:Subject|Issuer)(?:DN|X500Principal)\s*\(\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_dn_src, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:endsWith|startsWith|contains|indexOf|matches)\s*\(`, line)
	not helpers.is_comment_line(line)
	_dn_partial(lines, i, _strip(line))
	finding := _finding(path, i, line, _dn_msg)
}

_dn_partial(_, _, code) if {
	regex.match(concat("", [_dn_src, `\s*\.\s*(?:getName|toString)\s*\(\s*\)`, _partial]), code)
}

_dn_partial(lines, i, code) if {
	some v in helpers.tainted_vars(lines, i, 6, _dn_src)
	regex.match(concat("", [`\b`, v, _partial]), code)
}

# ── Python: hand-written hostname matcher ───────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?mi)^\s*(?:async\s+)?def\s+\w*(?:verify|check|match|validate)\w*host`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`(?i)^\s*(?:async\s+)?def\s+\w*(?:verify|check|match|validate)\w*host\w*\s*\(([^)]*)\)`, line, 1)
	count(m) > 0
	params := [p |
		some raw in split(m[0][1], ",")
		p := trim_space(regex.replace(raw, `[:=].*$`, ""))
		regex.match(`(?i)^\w*(?:host|server_name|sni|domain|expected)\w*$`, p)

		# a collection of hosts is an allowlist: membership in it is exact
		not regex.match(`(?i)(?:s|list|set|allowed\w*|allowlist|whitelist)$`, p)
	]
	count(params) > 0
	e := _body_end(lines, i, 20, `\S`)
	body := concat("\n", array.slice(lines, i + 1, e + 1))

	# a TLS identity check: the function handles a certificate, socket or SSL object
	regex.match(`(?i)cert|ssl|tls|peer|sock|x509|san\b|subjectAltName|commonName`, concat("\n", [line, body]))
	not regex.match(`match_hostname\s*\(|\.verify\w*\s*\(|verify_hostname\s*\(`, body)
	some j in numbers.range(i + 1, e)
	l := lines[j]
	not helpers.is_comment_line(l)
	code := _strip(l)
	some p in params
	_py_partial(code, p)
	finding := _finding(path, j, l, _host_msg)
}

_py_partial(code, p) if regex.match(concat("", [_host_re(p), `\s*\.\s*(?:endswith|startswith|find|rfind|index|__contains__)\s*\(`]), code)

_py_partial(code, p) if {
	regex.match(concat("", [`\b\w+(?:\.\w+|\[[^\]]*\])*\s+in\s+`, p, `\b`]), code)
	not regex.match(concat("", [`\bfor\s+[\w\s,()]+\s+in\s+`, p, `\b`]), code)
}

# Two hops: X500Principal p = cert.getSubjectX500Principal(); String dn = p.getName();
_dn_partial(lines, i, code) if {
	start := max([0, i - 6])
	i - 2 >= start
	some j in numbers.range(start, i - 2)
	regex.match(_dn_src, lines[j])
	not helpers.is_comment_line(lines[j])
	p := helpers.assigned_ident(lines[j])
	some k in numbers.range(j + 1, i - 1)
	regex.match(concat("", [`\b`, p, `\s*\.\s*(?:getName|toString)\s*\(`]), lines[k])
	v := helpers.assigned_ident(lines[k])
	regex.match(concat("", [`\b`, v, _partial]), code)
}

# A host name, possibly normalised first (hostname.toLowerCase(Locale.ROOT).endsWith(...)).
_host_re(host) := concat("", [`\b`, host, `(?:\s*\.\s*(?:toLowerCase|toUpperCase|trim|strip|intern|lower|casefold|rstrip)\s*\([^()]*\))*`])

# The certificate's name tested against the host: san.endswith(hostname)
_py_partial(code, p) if regex.match(concat("", [`\.\s*(?:endswith|startswith)\s*\(\s*`, p, `\s*[\),]`]), code)

_java_host_partial(host, code) if regex.match(concat("", [_host_re(host), _partial]), code)

# a certificate name tested against the host: cn.endsWith(hostname)
_java_host_partial(host, code) if regex.match(concat("", [`\.\s*(?:endsWith|startsWith)\s*\(\s*`, host, `\s*\)`]), code)
