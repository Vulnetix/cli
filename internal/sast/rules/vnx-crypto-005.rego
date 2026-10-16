package vulnetix.rules.vnx_crypto_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CRYPTO-005",
	"name": "TLS certificate validation disabled",
	"description": "A TLS client is configured to accept any certificate or any host name. Reported: Python verify=False passed to a call (requests, httpx and anything else taking the keyword) or assigned to .verify, ssl._create_unverified_context, check_hostname = False, verify_mode/cert_reqs set to CERT_NONE (also urllib3's 'CERT_NONE' string), urllib3 assert_hostname=False, aiohttp TCPConnector(ssl=False) and verify_ssl=False; Node.js rejectUnauthorized: false (object literal or assignment), process.env.NODE_TLS_REJECT_UNAUTHORIZED set to 0, request's strictSSL: false and a checkServerIdentity callback that returns nothing; Go InsecureSkipVerify: true or = true. Java (trust-all X509TrustManager, HostnameVerifier returning true, NoopHostnameVerifier, TrustAllStrategy/TrustSelfSignedStrategy, InsecureTrustManagerFactory and the rest) is reported by VNX-JAVA-006, not here. Not reported: a value taken from configuration (verify=self.verify, InsecureSkipVerify: opts.Insecure, rejectUnauthorized: isProd), an assignment made only inside an if/else branch (a library honouring its caller's verify option or an --insecure flag), a Go config that also installs VerifyPeerCertificate/VerifyConnection (custom pinning), a Node server that sets requestCert (optional client certificates), reading or comparing NODE_TLS_REJECT_UNAUTHORIZED, import lines, the text inside string literals and comments, documentation, and test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-crypto-005/",
	"languages": ["python", "node", "go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "certificate", "mitm", "transport-security"],
}

_lang(path) := "python" if endswith(path, ".py")

_lang(path) := "node" if {
	regex.match(`\.(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$`, path)
	not endswith(path, ".min.js")
}

_lang(path) := "go" if endswith(path, ".go")

# whole-file gate: at least one of the keywords a finding needs
_gate := {
	"python": `verify|CERT_NONE|check_hostname|_create_unverified_context|assert_hostname|TCPConnector`,
	"node": `rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|strictSSL|checkServerIdentity`,
	"go": `InsecureSkipVerify`,
}

_strings := {
	"python": `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`,
	"node": "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`",
	"go": "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`",
}

_tail_comment := {
	"python": `#.*$`,
	"node": `//.*$`,
	"go": `//.*$`,
}

# Literals that carry the setting become sentinels before strings are
# blanked: urllib3's "CERT_NONE", Node's env var key and its '0' value.
_code(lang, line) := c if {
	s1 := regex.replace(line, `['"]CERT_NONE['"]`, "__CERT_NONE__")
	s2 := regex.replace(s1, `\[\s*['"]NODE_TLS_REJECT_UNAUTHORIZED['"]\s*\]`, ".NODE_TLS_REJECT_UNAUTHORIZED")
	s3 := regex.replace(s2, `(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*)['"]0['"]`, "${1}0")
	t := regex.replace(s3, _strings[lang], `""`)
	c := regex.replace(t, _tail_comment[lang], "")
}

# ── patterns that report on their own line ─────────────────────────────
# Each entry: [pattern, is_assignment]. An assignment made only inside a
# conditional branch is an option being honoured, not a decision.
_pats := {
	"python": [
		[`(?:\(|,)\s*verify(?:_ssl)?\s*=\s*False\b`, false],
		[`^\s*verify(?:_ssl)?\s*=\s*False\s*[,)]`, false],
		[`\.verify\s*=\s*False\b`, true],
		[`\bssl\._create_unverified_context\b`, false],
		[`\bcheck_hostname\s*=\s*False\b`, true],
		[`\b(?:verify_mode|cert_reqs)\s*=\s*(?:ssl\.)?(?:CERT_NONE|__CERT_NONE__)\b`, true],
		[`\bassert_hostname\s*=\s*False\b`, false],
		[`\bTCPConnector\s*\([^)]*\bssl\s*=\s*False\b`, false],
	],
	"node": [
		[`\brejectUnauthorized\s*:\s*false\b`, false],
		[`\.rejectUnauthorized\s*=\s*false\b`, true],
		[`\bprocess\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0\b`, true],
		[`\bstrictSSL\s*:\s*false\b`, false],
		[`\bcheckServerIdentity\s*:\s*(?:\([^)]*\)|\w+)\s*=>\s*(?:undefined|null|\{\s*\})`, false],
		[`\bcheckServerIdentity\s*:\s*function\s*\([^)]*\)\s*\{\s*(?:return\s*(?:undefined|null)?\s*;?\s*)?\}`, false],
	],
	"go": [[`\bInsecureSkipVerify\s*(?::|=)\s*true\b`, true]],
}

_indent(l) := count(l) - count(trim_left(l, " \t"))

# The nearest less-indented code line above is an if/elif/else header.
_conditional(lines, i) if {
	i > 0
	ind := _indent(lines[i])
	ks := [k |
		some k in numbers.range(max([0, i - 8]), i - 1)
		t := trim_space(lines[k])
		t != ""
		not helpers.is_comment_line(lines[k])
		_indent(lines[k]) < ind
	]
	count(ks) > 0
	regex.match(`^\s*(?:\}\s*)?(?:if|elif|else)\b`, lines[ks[count(ks) - 1]])
}

_hit(lang, lines, i, code) if {
	some p in _pats[lang]
	regex.match(p[0], code)
	not _cond_excluded(p[1], lines, i)
}

_cond_excluded(true, lines, i) if _conditional(lines, i)

_excluded(_, _, _, code) if regex.match(`^\s*(?:import|from)\s`, code)

# Go: a custom verifier replaces the default chain check.
_excluded("go", lines, i, _) if {
	w := helpers.code_window(lines, i, 6, 6)
	regex.match(`\bVerify(?:PeerCertificate|Connection)\s*[:=]`, w)
}

# Node: a TLS server asking for optional client certificates.
_excluded("node", lines, i, _) if {
	w := helpers.code_window(lines, i, 4, 4)
	contains(w, "requestCert")
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_gate[lang], content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 1000
	regex.match(_gate[lang], line)
	not helpers.is_comment_line(line)
	code := _code(lang, line)
	_hit(lang, lines, i, code)
	not _excluded(lang, lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "TLS certificate or host-name verification is disabled here, so any certificate is accepted and the connection can be intercepted; keep verification on and trust a private CA bundle instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
