package vulnetix.rules.vnx_php_020

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-020",
	"name": "PHP curl SSL certificate verification disabled",
	"description": "TLS certificate or hostname verification is switched off for an outgoing HTTPS request: curl_setopt() or a curl_setopt_array() entry setting CURLOPT_SSL_VERIFYPEER or CURLOPT_SSL_VERIFYHOST to false, 0, '0', '' or null (also when the value is on the next line of a multi-line call); a Guzzle option 'verify' => false or RequestOptions::VERIFY => false (new Client([...]), ->request(), Laravel Http::withOptions()) in a file that uses Guzzle or the Laravel HTTP client; Laravel Http::withoutVerifying(); or a stream context / Symfony HttpClient option 'verify_peer' or 'verify_peer_name' => false. Any network attacker can then present their own certificate and read or alter the traffic. Not reported: verification enabled (true, VERIFYHOST 2, a CA bundle path), a value taken from a variable or configuration, test files, comments and string literals. CURLOPT_SSL_VERIFYHOST 1 is not reported: current libcurl treats it as 2.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-020/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [295],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "ssl", "curl", "mitm", "php"],
}

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

# The value position once string literals are blanked: false, null, 0, or a
# string ('0', '') which curl reads as 0.
_off := `\s*(?:(?i:false|null)\b|0\b)`

_curl_re := concat("", [`\\?\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)`, _off])

_gate_re := `CURLOPT_SSL_VERIFY|['"]verify(_peer|_peer_name)?['"]\s*=>|withoutVerifying|RequestOptions::VERIFY`

_guzzle_file_re := `GuzzleHttp|\bHttp::|withOptions\s*\(|new\s+Client\s*\(`

# '0' and '' read as 0 to curl; any other string literal is blanked.
_curl_norm(s) := _no_strings(regex.replace(s, `'0?'|"0?"`, "0"))

# The option and its value may be on consecutive lines of a multi-line call.
_win(lines, i, line) := concat(" ", [line, lines[i + 1]]) if {
	regex.match(`CURLOPT_SSL_VERIFY(?:PEER|HOST)\s*(?:,|=>)\s*$`, line)
	i + 1 < count(lines)
} else := line

_is("curl", line, win, _) if {
	contains(line, "CURLOPT_SSL_VERIFY")
	regex.match(_curl_re, _curl_norm(win))
}

_is("guzzle", line, _, _) if {
	contains(line, "RequestOptions::VERIFY")
	regex.match(`\bRequestOptions::VERIFY\s*=>\s*(?i:false)\b`, _no_strings(line))
}

_is("stream", line, _, _) if {
	regex.match(`['"]verify_peer(?:_name)?['"]\s*=>\s*(?i:false)\b`, line)
	regex.match(`""\s*=>\s*(?i:false)\b`, _no_strings(line))
}

_is("guzzle", line, _, content) if {
	regex.match(`['"]verify['"]\s*=>\s*(?i:false)\b`, line)
	regex.match(`""\s*=>\s*(?i:false)\b`, _no_strings(line))
	regex.match(_guzzle_file_re, content)
}

_is("laravel", line, _, _) if {
	contains(line, "withoutVerifying")
	regex.match(`->\s*withoutVerifying\s*\(|\bHttp::withoutVerifying\s*\(`, _no_strings(line))
}

_message := {
	"curl": "CURLOPT_SSL_VERIFYPEER/VERIFYHOST is disabled: curl accepts any certificate, so a network attacker can intercept the request; remove the option (or set VERIFYPEER true, VERIFYHOST 2) and use CURLOPT_CAINFO for a private CA",
	"guzzle": "Guzzle 'verify' => false disables TLS certificate validation; remove it or pass the path to a CA bundle instead",
	"laravel": "Http::withoutVerifying() disables TLS certificate validation for this request; remove it or configure a CA bundle with withOptions(['verify' => $path])",
	"stream": "Stream context 'verify_peer'/'verify_peer_name' => false disables TLS certificate validation; remove it and set 'cafile' for a private CA",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(_gate_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)verify`, line)
	not helpers.is_comment_line(line)
	some kind, _ in _message
	_is(kind, line, _win(lines, i, line), content)
	finding := {
		"rule_id": metadata.id,
		"message": _message[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
