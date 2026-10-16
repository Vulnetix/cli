# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_926

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-926",
	"name": "Android component exported with no permission protecting it",
	"description": "Reports an <activity>, <activity-alias>, <service>, <receiver> or <provider> in AndroidManifest.xml that declares android:exported=\"true\" and no android:permission (a provider without android:permission needs both android:readPermission and android:writePermission; with only one, its other side is open and it is reported): any app on the device can start, bind, broadcast to or query it (CWE-926). The finding is on the android:exported line, and the start tag may span several lines. Not reported: the launcher activity (an intent-filter with category LAUNCHER or LEANBACK_LAUNCHER, which must be exported), components that are not exported or protected by a permission, components of an <application> that declares android:permission (the default for every component), components the manifest merger removes (tools:node=\"remove\"), commented-out elements (single-line or inside a multi-line comment), and XML files other than AndroidManifest.xml. Components exported implicitly by an intent-filter on old target SDKs are not reported, because the target SDK is not known from the manifest line.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-926/",
	"languages": [],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [926],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["improper-export-android", "android", "cwe-926"],
}

_open_re := `<(activity-alias|activity|service|receiver|provider)\b`

_exported_re := `android:exported\s*=\s*["']true["']`

_perm_re := `android:(permission|readPermission|writePermission)\s*=`

# The line that closes the start tag opened at i (bounded).
_tag_end(lines, i, n) := min(array.concat([min([n, i + 30])], [j |
	some j in numbers.range(i, min([n, i + 30]))
	contains(lines[j], ">")
]))

# The line that closes the element (bounded); a self-closed tag has no body.
_elem_end(lines, e, n, elem) := min(array.concat([min([n, e + 60])], [j |
	some j in numbers.range(e, min([n, e + 60]))
	contains(lines[j], concat("", ["</", elem]))
]))

_in_comment(line) if startswith(trim_space(line), "<!--")

# Line i sits inside a multi-line <!-- ... --> block opened above (bounded).
_in_comment_block(lines, i) if {
	some j in numbers.range(max([0, i - 40]), i - 1)
	contains(lines[j], "<!--")
	parts := split(lines[j], "<!--")
	not contains(parts[count(parts) - 1], "-->")
	every k in helpers.span(j + 1, i - 1) {
		not contains(lines[k], "-->")
	}
	not _closed_before_tag(lines[i])
}

_closed_before_tag(line) if {
	contains(line, "-->")
	not regex.match(`<(activity|service|receiver|provider)[^>]*-->`, line)
	regex.match(`-->.*<(activity|service|receiver|provider)`, line)
}

# An android:permission on <application> is the default for every component.
_app_protected(lines, n) if {
	some i, l in lines
	contains(l, "<application")
	regex.match(`<application\b`, l)
	e := _tag_end(lines, i, n)
	regex.match(`android:permission\s*=`, concat("\n", array.slice(lines, i, e + 1)))
}

_protected(tag, _) if regex.match(`android:permission\s*=`, tag)

_protected(tag, elem) if {
	elem != "provider"
	regex.match(_perm_re, tag)
}

# A provider with no android:permission needs both a read and a write permission.
_protected(tag, "provider") if {
	regex.match(`android:readPermission\s*=`, tag)
	regex.match(`android:writePermission\s*=`, tag)
}

_launcher(lines, e, n, elem) if {
	not endswith(trim_space(lines[e]), "/>")
	some j in numbers.range(e, _elem_end(lines, e, n, elem))
	contains(lines[j], "android.intent.category.")
	regex.match(`android\.intent\.category\.(LEANBACK_)?LAUNCHER\b`, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(^|/)AndroidManifest\.xml$`, path)
	regex.match(_exported_re, content)
	lines := split(content, "\n")
	n := count(lines) - 1
	some i, line in lines
	contains(line, "<")
	m := regex.find_all_string_submatch_n(_open_re, line, 1)
	count(m) > 0
	elem := m[0][1]
	not _in_comment(line)
	not _in_comment_block(lines, i)
	e := _tag_end(lines, i, n)
	tag_lines := array.slice(lines, i, e + 1)
	tag := concat("\n", tag_lines)
	regex.match(_exported_re, tag)
	not _protected(tag, elem)
	not regex.match(`tools:node\s*=\s*["']remove["']`, tag)
	not _app_protected(lines, n)
	not _launcher(lines, e, n, elem)
	some k, tl in tag_lines
	regex.match(_exported_re, tl)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("<%s> is exported (android:exported=\"true\") with no android:permission, so any app on the device can reach it. Set android:exported=\"false\" or require a signature-level permission", [elem]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + k + 1,
		"snippet": tl,
	}
}
