# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1304

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1304",
	"name": "Security state restored from unprotected saved state",
	"description": "CWE-1304 (Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation) is a hardware weakness: configuration saved before a low-power state is restored afterwards without an integrity check. Its nearest statically recognisable software form is reported: Android Java/Kotlin code that restores a security decision (logged in, authenticated, admin, role, PIN or biometric verified, unlocked, premium/licensed, access level) from state saved across a process stop, with no integrity protection, instead of re-establishing it. Reported: getBoolean/getString/getInt with such a key (a literal, or a constant of this file whose value is one) on plain SharedPreferences (a variable typed SharedPreferences or assigned from getSharedPreferences/getDefaultSharedPreferences, or a call chained onto one, on the same or the next line), which any rooted device or backup restore can edit, and on a saved-instance Bundle (savedInstanceState, a variable typed Bundle) restored after process death, which skips re-authentication. Not reported: EncryptedSharedPreferences (authenticated encryption), keys that are not security decisions (theme, language, scroll position), the same getters on JSON responses or Intents, test code and comments. Hardware save/restore integrity itself is not observable in source and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1304/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1304],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["saved-state-integrity", "android", "cwe-1304"],
}

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".kt")

_key_re := `(?i)^(?:is_?|has_?|user_?|pref_?|key_?)*(?:logged_?in|log(?:ged)?_?on|signed_?in|authenticated|authed|authori[sz]ed|admin|administrator|superuser|root_?access|premium|pro_?user|paid|subscribed|licen[cs]ed|unlocked|pin_?(?:verified|ok|passed|entered)|biometric_?(?:ok|passed|verified|auth)|verified|role|access_?level|privileges?|permissions?|has_?access|session_?valid)$`

_getter := `\.get(?:Boolean|String|Int)\(\s*([^,)\s]+)`

# Receivers that are plain SharedPreferences or a saved Bundle.
_receivers(content, lines) := {v |
	some l in lines
	not contains(l, "Encrypted")
	m := regex.find_all_string_submatch_n(`\b(?:SharedPreferences|Bundle)\s+(\w+)\s*[=;,)]|\b(\w+)\s*:\s*(?:SharedPreferences|Bundle)\b\??|\b(?:val|var|SharedPreferences)?\s*(\w+)\s*(?:=|by\s+lazy\s*\{)\s*[\w.]*(?:get(?:Default)?SharedPreferences|getPreferences)\(`, l, -1)
	some x in m
	v := concat("", [x[1], x[2], x[3]])
	v != ""
} | {"savedInstanceState"}

# A key literal, or a constant whose literal is in this file.
_key(arg, _) := k if {
	regex.match(`^"[^"]*"$`, arg)
	k := trim(arg, `"`)
}

_key(arg, content) := k if {
	regex.match(`^[A-Za-z_][\w.]*$`, arg)
	parts := split(arg, ".")
	name := parts[count(parts) - 1]
	m := regex.find_all_string_submatch_n(concat("", [`\b`, name, `\s*(?::\s*\w+)?\s*=\s*"([^"]*)"`]), content, 1)
	count(m) > 0
	k := m[0][1]
}

_on_receiver(line, _, _, recvs) if {
	some r in recvs
	regex.match(concat("", [`\b`, r, `\s*\??\.get(?:Boolean|String|Int)\(`]), line)
}

_on_receiver(line, _, _, _) if regex.match(`(?:get(?:Default)?SharedPreferences|getPreferences)\([^;]*\)\s*\??\.get(?:Boolean|String|Int)\(`, line)

_on_receiver(line, lines, i, _) if {
	regex.match(`^\s*\??\.get(?:Boolean|String|Int)\(`, line)
	i > 0
	regex.match(`(?:get(?:Default)?SharedPreferences|getPreferences)\([^;]*\)\s*$`, lines[i - 1])
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	not helpers.is_test_path(path)
	regex.match(`SharedPreferences|Bundle|getPreferences\(`, content)
	regex.match(`\.get(?:Boolean|String|Int)\(`, content)
	lines := split(content, "\n")
	recvs := _receivers(content, lines)
	some i, line in lines
	contains(line, ".get")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_getter, line, -1)
	some x in m
	k := _key(x[1], content)
	regex.match(_key_re, k)
	_on_receiver(line, lines, i, recvs)
	not _encrypted_prefs(content, line)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security decision '%s' is restored from unprotected saved state; it can be edited on disk or survives process death without re-authentication. Re-establish it (re-authenticate, ask the server) or keep it in EncryptedSharedPreferences", [k]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# A file that builds EncryptedSharedPreferences reads its preferences through
# it; a Bundle read is still reported.
_encrypted_prefs(content, line) if {
	contains(content, "EncryptedSharedPreferences")
	not regex.match(`(?i)savedInstanceState|bundle|state\.get`, line)
}
