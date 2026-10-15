# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_412

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-412",
	"name": "Unrestricted Externally Accessible Lock",
	"description": "Reports Java locks that code outside the class can take and hold, blocking the class indefinitely. (1) `synchronized` on a JVM-wide shared object: a string literal, a String constant initialised from a literal (literals are interned), `x.intern()` or any `(expr).intern()`, `Boolean.TRUE/FALSE` or a boxed `valueOf(...)` cache. (2) A public lock field: `public ... Lock/ReentrantLock/ReadWriteLock/ReentrantReadWriteLock/StampedLock/Semaphore name`, or a `public Object name` that the class synchronizes on. (3) A public getter that hands out the lock or monitor (`public Lock getLock()`, `public Object getMonitor()`), including one Lombok generates from `@Getter` on a lock field (unless AccessLevel.PRIVATE/NONE). Not reported: `synchronized (this)`, synchronized methods and `synchronized (Foo.class)` (an ordinary, widely accepted idiom whose exposure depends on who holds references), private or package-private lock fields, test files, comments and strings. Locks exposed through other paths (a protected field used by subclasses, a lock passed out as an argument) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-412/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [412],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["unrestricted-lock", "cwe-412"],
}

_strip(l) := regex.replace(l, `"(\\.|[^"\\])*"`, `""`)

_report(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_shared_msg := "This block synchronizes on an object the whole JVM shares (an interned string, a Boolean or a boxed-value cache): any other code, including a library, can lock the same object and stall this class. Synchronize on a private final Object owned by this class."

_public_msg := "This lock is reachable from outside the class: any caller can acquire it and hold it, blocking every method that needs it. Keep the lock in a private final field and do not return it."

_lock_types := `(?:java\.util\.concurrent\.locks\.)?(?:Lock|ReentrantLock|ReadWriteLock|ReentrantReadWriteLock|StampedLock)|(?:java\.util\.concurrent\.)?Semaphore`

_sync_on_shared(code) if regex.match(`\bsynchronized\s*\(\s*(""|[\w.]+\.intern\(\s*\)|Boolean\.(TRUE|FALSE)|(Integer|Long|Short|Byte|Character|Boolean)\.valueOf\()`, code)

# synchronized ((prefix + id).intern()): any expression that ends interned.
_sync_on_shared(code) if regex.match(`\bsynchronized\s*\([^{;]*\.intern\(\s*\)\s*\)`, code)

# synchronized (NAME) where NAME is a String initialised from a literal.
_sync_on_string_const(content, code) if {
	some m in regex.find_all_string_submatch_n(`\bsynchronized\s*\(\s*(?:this\.)?([A-Za-z_]\w*)\s*\)`, code, -1)
	m[1] != "this"
	regex.match(concat("", [`\bString\s+`, m[1], `\s*=\s*"[^"]*"\s*;`]), content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "synchronized")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "synchronized")
	not helpers.is_comment_line(line)
	code := _strip(line)
	_shared(content, code)
	finding := _report(path, i, line, _shared_msg)
}

_shared(_, code) if _sync_on_shared(code)

_shared(content, code) if _sync_on_string_const(content, code)

# Public lock fields.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*public\s`, content)
	regex.match(`Lock|Semaphore|Object`, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_space(line), "public")
	m := regex.find_all_string_submatch_n(concat("", [`^\s*public\s+(?:(?:static|final|volatile|transient)\s+)*(`, _lock_types, `|Object)\s+([A-Za-z_]\w*)\s*[=;]`]), line, 1)
	count(m) > 0
	_exposed_field(content, m[0][1], m[0][2])
	finding := _report(path, i, line, _public_msg)
}

_exposed_field(_, t, _) if t != "Object"

_exposed_field(content, "Object", v) if {
	regex.match(concat("", [`\bsynchronized\s*\(\s*(this\.)?`, v, `\s*\)`]), content)
}

# Public getters that return the lock.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	regex.match(`(?i)get\w*(lock|mutex|monitor)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	startswith(trim_space(line), "public")
	regex.match(concat("", [`^\s*public\s+(?:(?:static|final|synchronized)\s+)*(?:`, _lock_types, `|Object)\s+get\w*(?:Lock|Mutex|Monitor)\s*\(\s*\)`]), line)
	finding := _report(path, i, line, _public_msg)
}

# Lombok @Getter on a lock field generates `public Lock getLock()`.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "Getter")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Getter")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`^\s*@(?:lombok\.)?Getter\b(?:\([^)]*\))?\s+(?:(?:private|protected|static|final|volatile|transient)\s+)*(`, _lock_types, `|Object)\s+([A-Za-z_]\w*)\s*[=;]`]), line, 1)
	count(m) > 0
	not regex.match(`AccessLevel\.(PRIVATE|NONE)`, line)
	_exposed_field(content, m[0][1], m[0][2])
	finding := _report(path, i, line, _public_msg)
}
