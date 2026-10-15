# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_514

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-514",
	"name": "Covert Channel: data encoded in sleep timing or DNS lookups",
	"description": "Python code that signals data through a channel not meant for it. Timing channel: time.sleep()/sleep()/asyncio.sleep() whose duration depends on one bit of data, either a loop variable iterating a binary representation (format(x, '08b'), bin(x), an f-string :08b, a bits variable assigned from one) or a shift-and-mask ((v >> i) & 1, v & (1 << i)) inline or assigned to a variable up to four lines above; a sleep call broken across lines is read with its two continuation lines. Files that drive hardware (importing RPi.GPIO, gpiozero, machine, board, digitalio, spidev, smbus, pigpio) are skipped for timing, since bit-banged pulse widths are their protocol. Storage channel: socket.gethostbyname()/gethostbyname_ex()/getaddrinfo() or dns.resolver.resolve()/query() (also on a resolver object) on a host name built (f-string, %, +, .format or \".\".join) from hex/base32/base64/hexlify-encoded data, inline or from a variable assigned such an encoding within 10 lines above. Not reported: random jitter and exponential backoff sleeps, sleeps that depend on ordinary values (priority, retry count), lookups of fixed or service host names, and the patterns in comments or string literals. Covert channels in other media (packet timing, file metadata) are not detected.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-514/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [514],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["covert-channel", "exfiltration", "cwe-514"],
}

_sleep_re := `(?:^|[^\w.])(?:(?:time|asyncio)\.)?sleep\s*\(`

_dns_re := `\bsocket\.(?:gethostbyname(?:_ex)?|getaddrinfo)\s*\(|\b(?:dns\.)?resolver\.(?:resolve|query)\s*\(`

_bit_iter_re := `format\s*\([^)]*["']0?\d*b["']|\bbin\s*\(|\{[^{}]*:0?\d*b\}|\bbits\b|>>`

_encoder_re := `\.hex\s*\(\s*\)|\b(?:b32encode|b64encode|urlsafe_b64encode|b16encode|b85encode|hexlify)\s*\(`

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# Text after the call opens on the raw line (literals kept: an f-string host
# name is the argument).
_args(re, line) := concat(" ", array.slice(parts, 1, count(parts))) if parts := regex.split(re, line)

# ── Timing channel ───────────────────────────────────────────────────────

_bit_mask_re := `>>[^&]{0,20}&\s*1\b|&\s*\(\s*1\s*<<`

# A hardware driver bit-bangs a wire protocol whose pulse width is the bit
# (WS2812, one-wire): that is the intended channel, not a covert one.
_hardware_io(content) if regex.match(`(?m)^\s*(?:import\s+(?:RPi\.GPIO|gpiozero|spidev|smbus2?|board|digitalio|machine|pigpio)\b|from\s+(?:RPi|gpiozero|machine|board|digitalio|pigpio)\b)`, content)

_hw(content) := true if _hardware_io(content)

else := false

# The sleep's arguments, including up to two continuation lines when the
# call is broken after its opening parenthesis.
_sleep_args(lines, i, line) := args if {
	not regex.match(`\(\s*$`, line)
	args := _args(_sleep_re, line)
}

_sleep_args(lines, i, line) := args if {
	regex.match(`\(\s*$`, line)
	args := concat(" ", array.concat([_args(_sleep_re, line)], array.slice(lines, i + 1, i + 3)))
}

_reported(lines, i, line, c, hw) if {
	not hw
	regex.match(_sleep_re, c)
	args := _sleep_args(lines, i, line)
	regex.match(_bit_mask_re, args)
}

# Two lines: bit = (byte >> k) & 1, then sleep(LONG if bit else SHORT).
_reported(lines, i, line, c, hw) if {
	not hw
	regex.match(_sleep_re, c)
	args := _sleep_args(lines, i, line)
	some j in numbers.range(max([0, i - 4]), i - 1)
	regex.match(_bit_mask_re, lines[j])
	not helpers.is_comment_line(lines[j])
	v := helpers.assigned_ident(lines[j])
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

_reported(lines, i, line, c, hw) if {
	not hw
	regex.match(_sleep_re, c)
	args := _sleep_args(lines, i, line)
	some j in numbers.range(max([0, i - 6]), i - 1)
	m := regex.find_all_string_submatch_n(`^\s*for\s+(\w+)\s+in\s+(.+):`, lines[j], 1)[0]
	v := m[1]
	regex.match(concat("", [`\b`, v, `\b`]), args)
	_bit_iterable(lines, j, m[2])
}

_bit_iterable(_, _, it) if regex.match(_bit_iter_re, it)

_bit_iterable(lines, j, it) if {
	name := trim_space(it)
	regex.match(`^\w+$`, name)
	some k in numbers.range(max([0, j - 10]), j)
	helpers.assigned_ident(lines[k]) == name
	regex.match(_bit_iter_re, lines[k])
}

# ── DNS storage channel ──────────────────────────────────────────────────

_built(args) if regex.match(`^\s*(?:f["']|["']\.["']\s*\.join\s*\(|[^,]*(?:%|\+|\.format\s*\())`, args)

_reported(lines, i, line, c, hw) if {
	regex.match(_dns_re, c)
	args := _args(_dns_re, line)
	_built(args)
	regex.match(_encoder_re, args)
}

_reported(lines, i, line, c, hw) if {
	regex.match(_dns_re, c)
	args := _args(_dns_re, line)
	_built(args)
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_encoder_re, prev)
	v := helpers.assigned_ident(prev)
	regex.match(concat("", [`\b`, v, `\b`]), args)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`sleep\s*\(|gethostbyname|getaddrinfo|resolver\.`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`sleep|gethostbyname|getaddrinfo|resolver\.`, line)
	not helpers.is_comment_line(line)
	c := _code(line)
	_reported(lines, i, line, c, _hw(content))
	finding := {
		"rule_id": metadata.id,
		"message": "Data is encoded into sleep timing or DNS query names: this is a covert channel. Remove it, or send the data over an authenticated, logged channel",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
