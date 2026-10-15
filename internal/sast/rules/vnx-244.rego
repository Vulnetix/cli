# SPDX-License-Identifier: Apache-2.0
# CWE-244: Improper Clearing of Heap Memory Before Release ('Heap Inspection')

package vulnetix.rules.vnx_244

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-244",
	"name": "Secret left in heap memory when it is released",
	"description": "Heap memory holding a password, passphrase, PIN, secret or key is released without being wiped, so the plaintext stays in freed memory where a heap dump, a core file, swap or a later allocation can read it. Reported in C and C++: free()/std::free()/g_free()/OPENSSL_free()/delete/delete[] of a variable or field whose name ends in password, passwd, pwd, pw, passphrase, pin, secret, session_key, master_key, aes_key, private_key/priv_key, enc_key, sym_key, key_material, plaintext, cleartext or credential(s) (optionally followed by _buf/buffer), when none of memset/memset_s/explicit_bzero/bzero/SecureZeroMemory/OPENSSL_cleanse/sodium_memzero/mbedtls_platform_zeroize, nor a project wipe helper whose name contains zero, wipe, cleanse, scrub or burn (secure_zero, crypto_wipe), names it in the 15 lines above; and realloc() of such a buffer, which frees the old block without wiping it. In Java: a char[] password from JPasswordField.getPassword() or Console.readPassword() turned into an immutable String with new String(...)/String.valueOf(...)/String.copyValueOf(...), directly or through a char[] variable assigned from one up to 10 lines above, which can never be cleared. Not reported: buffers wiped before release (a wipe that the optimiser may delete as a dead store is VNX-CWE1037-AUTO's concern), sodium_free/OPENSSL_clear_free/clear_free, which wipe themselves, ordinary names such as key, token or table, hardware pins (gpio_pin, led_pin, reset_pin), a char[] cleared with Arrays.fill, comments, strings and test code. Languages without manual memory management (Go, Python, JavaScript, PHP, Ruby) cannot clear heap memory reliably and are not covered.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-244/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [244],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["memory", "secrets", "heap-inspection", "cwe-244"],
}

_c_file(path) if regex.match(`\.(c|h|cc|cpp|cxx|hpp|hh)$`, path)

# The last component of the released expression names a secret.
_secret_name := `(?i)(password|passwd|passphrase|pwd|secret|session_?key|master_?key|aes_?key|priv(?:ate)?_?key|enc(?:ryption)?_?key|sym(?:metric)?_?key|key_?material|plaintext|cleartext|credentials?|(?:^|_)pw|(?:^|_)pin)(?:_?buf(?:fer)?)?_?$`

# Cheap whole-file prefilter for the names above.
_secret_word := `(?i:passw|passphrase|pwd|secret|session_?key|master_?key|aes_?key|priv(?:ate)?_?key|enc(?:ryption)?_?key|sym(?:metric)?_?key|key_?material|plaintext|cleartext|credential|\bpin\b|\bpw\b|\bpw_|_pin\b|_pw\b)`

_free_re :=`(?:^|[;{}\s])(?:std::)?(?:free|g_free|OPENSSL_free|zfree)\s*\(\s*([A-Za-z_][\w\.\->\[\]]*)\s*\)\s*;`

_delete_re := `(?:^|[;{}\s])delete\s*(?:\[\s*\])?\s*([A-Za-z_][\w\.\->]*)\s*;`

_realloc_re := `\brealloc\s*\(\s*([A-Za-z_][\w\.\->]*)\s*,`

_released(line) := e if {
	m := regex.find_all_string_submatch_n(_free_re, line, 1)
	count(m) > 0
	e := m[0][1]
}

_released(line) := e if {
	m := regex.find_all_string_submatch_n(_delete_re, line, 1)
	count(m) > 0
	e := m[0][1]
}

_release_candidate(line) if contains(line, "free")

_release_candidate(line) if contains(line, "delete")

_last_component(e) := c if {
	parts := regex.split(`->|\.`, e)
	c := parts[count(parts) - 1]
}

_secret(e) if {
	c := _last_component(e)
	regex.match(_secret_name, c)
	not regex.match(_hw_pin, c)
}

# A GPIO/board pin is hardware, not a PIN.
_hw_pin := `(?i)(?:gpio|led|io|irq|pwm|rst|reset|cs|en|enable|clk|sda|scl|tx|rx|out|output|in|input|button|btn|sensor|mux|data|int|wake|power|pwr)_?pin_?$`

_wipe_re := `(?i:\b\w*(?:zero|wipe|cleanse|scrub|burn)\w*\s*\()|\b(memset|memset_s|explicit_bzero|bzero|SecureZeroMemory|RtlSecureZeroMemory|OPENSSL_cleanse|sodium_memzero|mbedtls_platform_zeroize|explicit_memset|memzero_explicit)\s*\(`

_wiped(lines, i, e) if {
	i > 0
	some j in numbers.range(max([0, i - 15]), i - 1)
	regex.match(_wipe_re, lines[j])
	contains(lines[j], _last_component(e))
	not helpers.is_comment_line(lines[j])
}

_message := "Secret buffer released without wiping it first; clear it with explicit_bzero/memset_s/OPENSSL_cleanse (or sodium_free) before free so the plaintext does not linger in heap memory"

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(concat("", [`(?:free\s*\(|delete\b)[^\n;]*`, _secret_word]), content)
	lines := split(content, "\n")
	some i, line in lines
	_release_candidate(line)
	not helpers.is_comment_line(line)
	e := _released(line)
	_secret(e)
	not _wiped(lines, i, e)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(concat("", [`realloc\s*\([^,\n]*`, _secret_word]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "realloc")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_realloc_re, line, 1)
	count(m) > 0
	_secret(m[0][1])
	finding := {
		"rule_id": metadata.id,
		"message": "realloc() of a buffer holding a secret frees the old block without wiping it; allocate a new buffer, copy, wipe the old one with explicit_bzero/OPENSSL_cleanse and free it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java two-line form: a char[] taken from getPassword()/readPassword() a few
# lines above, then turned into a String.
_java_pw_var := `\b([A-Za-z_]\w*)\s*=\s*(?:[\w\.]+\.getPassword\(\)|(?:[\w\.]+\.)?readPassword\()`

_java_var_to_string := `\b(?:new\s+String|String\.valueOf|String\.copyValueOf)\s*\(\s*([A-Za-z_]\w*)\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`JPasswordField|readPassword|PasswordCallback`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "String")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_java_var_to_string, line, 1)
	count(m) > 0
	v := m[0][1]
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	am := regex.find_all_string_submatch_n(_java_pw_var, lines[j], 1)
	count(am) > 0
	am[0][1] == v
	finding := {
		"rule_id": metadata.id,
		"message": "Password char[] converted to an immutable String that can never be wiped from the heap; keep it as char[] and clear it with Arrays.fill after use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: a char[] password turned into a String, which cannot be cleared.
_java_to_string := `\b(?:new\s+String|String\.valueOf|String\.copyValueOf)\s*\(\s*(?:[\w\.]+\.getPassword\(\)|(?:[\w\.]+\.)?readPassword\([^)]*\))\s*\)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`JPasswordField|readPassword|PasswordCallback`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "String")
	not helpers.is_comment_line(line)
	regex.match(_java_to_string, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Password char[] converted to an immutable String that can never be wiped from the heap; keep it as char[] and clear it with Arrays.fill after use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
