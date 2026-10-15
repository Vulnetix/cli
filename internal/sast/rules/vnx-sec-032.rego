package vulnetix.rules.vnx_sec_032

import rego.v1
import data.vulnetix.helpers
import data.vulnetix.lib.secrets

metadata := {
	"id": "VNX-SEC-032",
	"name": "PGP private key block hardcoded",
	"description": "Reports the armour header of a PGP/GPG private key block (-----BEGIN PGP PRIVATE KEY BLOCK-----) when key material follows it: a base64 line of at least 40 characters within the next eight lines (armoured files, YAML block scalars, quoted multi-line .env values, Go/JS backtick, Python triple-quoted and heredoc strings that open on the header line), or on the same line after escaped newlines (JSON and single-line strings). A header used as a string constant or prefix check in code, documentation with a placeholder body, PGP public key blocks, and test and fixture paths are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-032/",
	"languages": ["generic"],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [321],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secret", "pgp", "private-key", "credentials"],
}

_header := "-----BEGIN PGP PRIVATE KEY BLOCK-----"

# Header followed on the same line by escaped newlines and key material.
_inline_re := `-----BEGIN PGP PRIVATE KEY BLOCK-----(?:\\r)?\\n(?:(?:\\r)?\\n|[A-Za-z-]+: [^\\]*(?:\\r)?\\n)*[A-Za-z0-9+/]{40,}`

# Header that opens a block of its own (optionally indented, quoted or
# assigned, as in KEY="-----BEGIN ..., const k = `-----BEGIN ... or
# KEY = """-----BEGIN ...).
_own_line_re := `^\s*(?:[A-Za-z_][A-Za-z0-9_.\[\]<>]*\s+){0,3}(?:[A-Za-z_][A-Za-z0-9_.-]*\s*(?::\s*[A-Za-z_][A-Za-z0-9_.]*\s*)?(?::=|[:=])\s*)?(?:"""|'''|[@r]?#*["'\x60|>])?\s*-----BEGIN PGP PRIVATE KEY BLOCK-----\s*$`

_body_re := `^\s*["']?[A-Za-z0-9+/]{40,}={0,2}\s*$`

_has_body(lines, i) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 8]))
	regex.match(_body_re, lines[j])
}

_reportable(lines, i, line) if regex.match(_inline_re, line)

_reportable(lines, i, line) if {
	regex.match(_own_line_re, line)
	_has_body(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	not secrets.skip_path(path)
	not helpers.is_test_path(path)
	contains(content, _header)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _header)
	_reportable(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "PGP private key block detected in source; revoke on keyservers, generate a new key pair, and never commit private keys",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": secrets.redact(line),
	}
}
