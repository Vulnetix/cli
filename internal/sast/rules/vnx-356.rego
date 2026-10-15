# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_356

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-356",
	"name": "Electron app silently grants permissions or accepts invalid certificates",
	"description": "An Electron main process answers a security prompt on the user's behalf, so the user is never warned that a site wants the camera, microphone, geolocation or notifications, or that a TLS certificate is invalid. Reported in JavaScript/TypeScript: session.setPermissionRequestHandler(...) whose handler calls its callback with true unconditionally; setPermissionCheckHandler(...) whose handler returns true unconditionally; app.on / webContents.on('certificate-error', ...) whose handler calls its callback with true unconditionally; setCertificateVerifyProc(...) whose handler calls its callback with 0 unconditionally; and app.commandLine.appendSwitch('ignore-certificate-errors'). A handler body (followed up to eight lines) that contains a condition, ternary, comparison, allowlist lookup or switch is treated as a decision and not reported, nor is a callback given false, nor the ignore-certificate-errors switch inside a development-only branch (!app.isPackaged, isDev, NODE_ENV === 'development' within three lines above), nor are test files, comments and calls written inside string literals. TypeScript-typed handler parameters (callback: (granted: boolean) => void) are read through, the callback is taken from Electron's parameter position (so trailing details/isMainFrame parameters do not hide it), and app.on( with 'certificate-error' on the next line is followed. A handler passed by name (setPermissionRequestHandler(grantAll)) is not followed. Web UI confirmation dialogs are not judged: whether a prompt is warranted is a design question no line of code answers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-356/",
	"languages": ["node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [356],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["missing-unsafe-warning", "electron", "permissions", "tls", "cwe-356"],
}

_lang(path) if regex.match(`\.(js|mjs|cjs|jsx|ts|tsx|mts|cts)$`, path)

_file_gate := `setPermissionRequestHandler|setPermissionCheckHandler|certificate-error|setCertificateVerifyProc|ignore-certificate-errors`

_strip(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\x60[^\x60]*\x60`, `""`)

# Body of the call opened on line i: lines i..i+k until the parentheses balance.
_body(lines, i) := concat("\n", array.slice(lines, i, i + n)) if {
	end := min([count(lines), i + 9])
	opens := [k |
		some k in numbers.range(i, end - 1)
		txt := _strip(concat("\n", array.slice(lines, i, k + 1)))
		count(regex.find_all_string_submatch_n(`\(`, txt, -1)) <= count(regex.find_all_string_submatch_n(`\)`, txt, -1))
	]
	n := _first_or(opens, end - 1) - i + 1
}

_first_or(arr, d) := arr[0] if count(arr) > 0

_first_or(arr, d) := d if count(arr) == 0

_decides(body) if regex.match(`\bif\s*\(|\?[^.]|&&|\|\||[=!]==?|\bswitch\s*\(|\.(?:has|includes|indexOf|startsWith|endsWith|test|match)\(|\bin\s+\w`, _strip(body))

# The callback parameter of the handler (see _pick).
_cb_param(body, idx) := p if {
	# drop TypeScript function-type annotations (callback: (granted: boolean) => void)
	plain := regex.replace(body, `:\s*\([^()]*\)\s*=>\s*[\w<>\[\]|]+`, ": fn")
	m := regex.find_all_string_submatch_n(`(?:\(([^()]*)\)\s*(?::\s*[\w<>\[\]]+\s*)?=>|function\s*\w*\s*\(([^()]*)\))`, plain, 1)
	count(m) > 0
	params := concat("", [m[0][1], m[0][2]])
	parts := [trim_space(regex.replace(s, `:.*$`, "")) | some s in split(params, ",")]
	nonempty := [s | some s in parts; s != ""]
	count(nonempty) > 0
	p := _pick(nonempty, idx)
	regex.match(`^[A-Za-z_$][\w$]*$`, p)
}

# Electron passes the callback at a fixed position (permission request: 3rd,
# before `details`; certificate-error: 6th, before `isMainFrame`; verify proc:
# 2nd). A handler that declares fewer parameters names it last.
_pick(params, idx) := params[idx] if count(params) > idx

_pick(params, idx) := params[count(params) - 1] if count(params) <= idx

# The call must be code, not text inside a string literal.
_kind_at(lines, i, line) := k if k := _kind(line)

# app.on(
#   "certificate-error", ...
_kind_at(lines, i, line) := "certificate-error" if {
	regex.match(`\.on\(\s*$`, line)
	nxt := helpers.next_code_index(lines, i, 2)
	regex.match(`^\s*['"]certificate-error['"]`, lines[nxt])
}

# The call must be code, not text inside a string literal.
_kind(line) := "permission-request" if contains(_strip(line), "setPermissionRequestHandler(")

_kind(line) := "permission-check" if contains(_strip(line), "setPermissionCheckHandler(")

_kind(line) := "certificate-error" if {
	regex.match(`\.on\(\s*['"]certificate-error['"]`, line)
	regex.match(`\.on\(\s*""`, _strip(line))
}

_kind(line) := "verify-proc" if contains(_strip(line), "setCertificateVerifyProc(")

_kind(line) := "switch" if {
	regex.match(`appendSwitch\(\s*['"]ignore-certificate-errors['"]`, line)
	regex.match(`appendSwitch\(\s*""`, _strip(line))
}

_dev_switch("switch", lines, i) if _dev_only(lines, i)

# The switch is set only in an unpackaged / development build.
_dev_only(lines, i) if {
	start := max([0, i - 3])
	some j in numbers.range(start, i)
	regex.match(`!\s*app\.isPackaged\b|\bisDev(?:elopment)?\b|NODE_ENV\s*===?\s*['"](?:development|dev)['"]|\bis\.dev\b`, lines[j])
}

_unsafe("switch", _) := "Chromium is started with --ignore-certificate-errors: every invalid TLS certificate is accepted without warning the user"

_unsafe("permission-request", body) := "Permission requests are granted unconditionally: the user is never asked before a page gets the camera, microphone, location or notifications. Allow only named permissions for trusted origins" if {
	not _decides(body)
	p := _cb_param(body, 2)
	regex.match(concat("", [`\b`, p, `\s*\(\s*true\s*\)`]), body)
}

_unsafe("permission-check", body) := "Permission checks always return true: every origin is treated as already granted, with no prompt. Return true only for named permissions and trusted origins" if {
	not _decides(body)
	regex.match(`=>\s*\(?\s*true\b|\breturn\s+true\b`, body)
}

_unsafe("certificate-error", body) := "Certificate errors are accepted unconditionally: the user is never warned about an invalid or intercepted TLS certificate. Accept only a pinned certificate for a known host" if {
	not _decides(body)
	p := _cb_param(body, 5)
	regex.match(concat("", [`\b`, p, `\s*\(\s*true\s*\)`]), body)
}

_unsafe("verify-proc", body) := "The certificate verifier always returns 0 (success): every certificate is trusted without warning the user. Return 0 only for a pinned certificate, -3 to use Chromium's verification" if {
	not _decides(body)
	p := _cb_param(body, 1)
	regex.match(concat("", [`\b`, p, `\s*\(\s*0\s*\)`]), body)
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(_file_gate, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_line_gate(lines, i, line)
	not helpers.is_comment_line(line)
	kind := _kind_at(lines, i, line)
	msg := _unsafe(kind, _body(lines, i))
	not _dev_switch(kind, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_line_gate(_, _, line) if regex.match(_file_gate, line)

_line_gate(lines, i, line) if {
	regex.match(`\.on\(\s*$`, line)
	i + 1 < count(lines)
	contains(lines[i + 1], "certificate-error")
}
