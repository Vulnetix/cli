# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_920

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-920",
	"name": "Android wake lock acquired without a timeout",
	"description": "An Android PowerManager.WakeLock or WifiManager.WifiLock is acquired with acquire() and no timeout, so if the release is skipped (an exception, an early return, a killed callback) the device stays awake or the Wi-Fi radio stays on until the process dies and drains the battery (CWE-920, Improper Restriction of Power Consumption). Reported in Java and Kotlin: X.acquire() (also X?.acquire(), X!!.acquire(), this.X.acquire()) with no argument where X is declared as a WakeLock/WifiLock or assigned from newWakeLock()/createWifiLock() in the same file, newWakeLock(...).acquire() chained, and a bare acquire() or it.acquire() inside a Kotlin apply/also/run/let block opened on a newWakeLock line or on its own chain line right after one. Not reported: acquire(timeout), Semaphore/lock/pool acquire() on other receivers, test files, comments and strings. Whether a release() follows is not judged; Android lint's WakelockTimeout check applies the same standard.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-920/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [920],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["android", "wakelock", "power-consumption", "cwe-920"],
}

_decl_res := [
	`\b(?:WakeLock|WifiLock)\s+([A-Za-z_]\w*)\s*[;=,)]`,
	`\b([A-Za-z_]\w*)\s*:\s*(?:PowerManager\.|WifiManager\.)?(?:WakeLock|WifiLock)\b`,
	`\b([A-Za-z_]\w*)\s*=\s*[^;\n]*\b(?:newWakeLock|createWifiLock)\s*\(`,
]

_lock_names(content) := {n |
	some re in _decl_res
	some m in regex.find_all_string_submatch_n(re, content, -1)
	n := m[1]
}

_hit(line, names, _, _) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)(?:\?|!!)?\.acquire\(\s*\)`, line, -1)
	m[1] in names
}

_hit(line, _, _, _) if regex.match(`\b(?:newWakeLock|createWifiLock)\s*\([^;]*\)\??\.acquire\(\s*\)`, line)

# Kotlin: pm.newWakeLock(...).apply { acquire() }
_hit(line, _, lines, i) if {
	regex.match(`^\s*acquire\(\s*\)\s*$`, line)
	some j in numbers.range(max([0, i - 3]), i - 1)
	regex.match(`\b(?:newWakeLock|createWifiLock)\s*\(.*\)\s*\.(?:apply|also|run)\s*\{\s*$`, lines[j])
}

# The same scope function on its own line of a chain:
#     .newWakeLock(PARTIAL_WAKE_LOCK, "tag")
#     .also { it.acquire() }
_hit(line, _, lines, i) if {
	regex.match(`^\s*(?:(?:\.(?:apply|also|run|let)\s*\{\s*)?(?:it\.)?)acquire\(\s*\)\s*\}?\s*$`, line)
	some j in numbers.range(max([0, i - 3]), i)
	regex.match(`^\s*\.(?:apply|also|run|let)\s*\{`, lines[j])
	k := max([0, j - 2])
	regex.match(`\b(?:newWakeLock|createWifiLock)\s*\(`, concat("\n", array.slice(lines, k, j)))
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in {".java", ".kt"}
	endswith(path, ext)
	not helpers.is_test_path(path)
	regex.match(`\b(?:WakeLock|WifiLock|newWakeLock|createWifiLock)\b`, content)
	contains(content, "acquire(")
	names := _lock_names(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "acquire(")
	not helpers.is_comment_line(line)
	code := regex.replace(line, `"[^"]*"`, `""`)
	_hit(code, names, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Wake lock (or Wi-Fi lock) acquired without a timeout: if release() is skipped the device stays awake and drains the battery. Use acquire(timeoutMillis) and release in finally",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
