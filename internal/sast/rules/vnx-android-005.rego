package vulnetix.rules.vnx_android_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-ANDROID-005",
	"name": "Android app permits cleartext HTTP traffic",
	"description": "A production Android app opts back in to unencrypted HTTP. Reported: cleartextTrafficPermitted=\"true\" on the <base-config> of a network security configuration, or on a <domain-config> that names at least one host other than loopback or the emulator's host alias (localhost, 127.0.0.1, ::1, 10.0.2.2, 10.0.3.2); and android:usesCleartextTraffic=\"true\" on an <application> that declares no android:networkSecurityConfig. Not reported: \"false\" values and debug-overrides, a domain-config for loopback hosts only, usesCleartextTraffic beside a networkSecurityConfig (which takes precedence on API 24+ and is judged on its own lines), files in debug/test source sets (src/debug, src/androidTest, src/test) and test, sample, example or demo modules, XML comments, and the attribute text in Java/Kotlin strings. The platform default (cleartext blocked from API 28) is not reported, and whether an http:// URL in code is reachable is not judged here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-android-005/",
	"languages": ["android"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [319],
	"capec": ["CAPEC-94"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["android", "cleartext", "network-security", "mobile-security"],
}

_nonprod(path) if helpers.is_test_path(path)

_nonprod(path) if regex.match(`(^|/)src/(debug|androidTest|test|testFixtures|[A-Za-z]+Debug)/`, path)

_nonprod(path) if regex.match(`(?i)(^|/)([\w.]*[-_.])?(tests?|testing|samples?|examples?|demos?)([-_.][\w.-]*)?/`, path)

_in_comment(lines, i) if startswith(trim_space(lines[i]), "<!--")

_in_comment(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	contains(lines[j], "<!--")
	parts := split(lines[j], "<!--")
	not contains(parts[count(parts) - 1], "-->")
	not _closed_between(lines, j + 1, i - 1)
}

_closed_between(lines, a, b) if {
	a <= b
	some k in numbers.range(a, b)
	contains(lines[k], "-->")
}

# ── Network security configuration ──────────────────────────────────────

_nsc_re := `cleartextTrafficPermitted\s*=\s*["']true["']`

_loopback := {"localhost", "127.0.0.1", "::1", "[::1]", "10.0.2.2", "10.0.3.2"}

# The element that carries the attribute: the nearest base-config or
# domain-config start at or above line i.
_element(lines, i) := e if {
	cands := [j | some j in numbers.range(max([0, i - 5]), i); regex.match(`<(base|domain)-config\b`, lines[j])]
	count(cands) > 0
	ms := regex.find_all_string_submatch_n(`<(base|domain)-config\b`, lines[max(cands)], -1)
	e := ms[count(ms) - 1][1]
}

_domains(lines, i) := ds if {
	text := concat("\n", array.slice(lines, i, min([count(lines), i + 40])))
	parts := split(text, "</domain-config>")
	ds := {trim_space(m[1]) | some m in regex.find_all_string_submatch_n(`<domain\b[^>]*>([^<]*)</domain>`, parts[0], -1)}
}

_loopback_only(lines, i) if {
	ds := _domains(lines, i)
	count(ds) > 0
	every d in ds {
		lower(d) in _loopback
	}
}

_nsc_reportable(lines, i) if _element(lines, i) == "base"

_nsc_reportable(lines, i) if {
	_element(lines, i) == "domain"
	not _loopback_only(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".xml")
	not _nonprod(path)
	contains(content, "cleartextTrafficPermitted")
	contains(content, "<network-security-config")
	regex.match(_nsc_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cleartextTrafficPermitted")
	regex.match(_nsc_re, line)
	not _in_comment(lines, i)
	_nsc_reportable(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The network security configuration permits cleartext HTTP: anyone on the network path can read and rewrite that traffic, including credentials and session tokens. Set cleartextTrafficPermitted=\"false\" and serve these hosts over HTTPS",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── AndroidManifest.xml ─────────────────────────────────────────────────

_uses_re := `android:usesCleartextTraffic\s*=\s*["']true["']`

_app_tag(lines, i) := tag if {
	opens := [j | some j in numbers.range(max([0, i - 40]), i); contains(lines[j], "<application")]
	count(opens) > 0
	s := max(opens)
	text := concat("\n", array.slice(lines, s, min([count(lines), s + 60])))
	ms := regex.find_n(`<application\b[^>]*>`, text, 1)
	count(ms) > 0
	tag := ms[0]
}

_has_nsc(lines, i) if contains(_app_tag(lines, i), "android:networkSecurityConfig")

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(^|/)AndroidManifest\.xml$`, path)
	not _nonprod(path)
	contains(content, "usesCleartextTraffic")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "usesCleartextTraffic")
	regex.match(_uses_re, line)
	not _in_comment(lines, i)
	not _has_nsc(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "android:usesCleartextTraffic=\"true\" lets every connection the app makes fall back to plain HTTP, which anyone on the network path can read and rewrite. Remove it (or set it to false) and serve every host over HTTPS; if one legacy host needs HTTP, scope it in a network security configuration",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
