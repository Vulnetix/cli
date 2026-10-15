# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1063

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1063",
	"name": "Creation of Class Instance within a Static Code Block",
	"description": "Java: a `static { ... }` initializer constructs an object (`new Type(...)`) of an application or library class. The object is built when the class is first loaded, on whatever thread touches it first, before any configuration or dependency injection runs; a failure surfaces as ExceptionInInitializerError and leaves the class unusable, and the instance cannot be replaced in tests. Not reported: the JDK containers and value types a static block normally fills (HashMap, ArrayList, HashSet, StringBuilder, Object, boxed numbers, atomics, locks), exceptions being thrown, arrays, `new` in instance initializers, static methods or static field initializers outside a static block, and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1063/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1063],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["class-instance-in-static-block", "initialization", "java", "cwe-1063"],
}

_benign := {
	"HashMap", "LinkedHashMap", "TreeMap", "ConcurrentHashMap", "EnumMap", "IdentityHashMap",
	"WeakHashMap", "Hashtable", "Properties", "ArrayList", "LinkedList", "ArrayDeque", "Vector",
	"Stack", "CopyOnWriteArrayList", "CopyOnWriteArraySet", "ConcurrentLinkedQueue", "HashSet",
	"LinkedHashSet", "TreeSet", "ConcurrentSkipListMap", "ConcurrentSkipListSet", "PriorityQueue",
	"BitSet", "Object", "String", "StringBuilder", "StringBuffer", "Integer", "Long", "Short",
	"Byte", "Double", "Float", "Character", "Boolean", "BigDecimal", "BigInteger", "AtomicInteger",
	"AtomicLong", "AtomicBoolean", "AtomicReference", "ReentrantLock", "ReentrantReadWriteLock",
	"ThreadLocal", "SimpleEntry", "Pair",
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_strip(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# Lines k..e of a static initializer opened at line k.
_block(lines, k) := [k, k] if {
	regex.match(`^\s*static\s*\{.*\}\s*$`, _strip(lines[k]))
}

_block(lines, k) := [k, e] if {
	s := _strip(lines[k])
	_opens(lines, k, s)
	ik := _indent(lines[k])
	n := count(lines)
	ends := [m |
		some m in numbers.range(k + 1, min([n - 1, k + 200]))
		_indent(lines[m]) <= ik
		startswith(trim_space(lines[m]), "}")
	]
	count(ends) > 0
	e := min(ends)
}

_opens(_, _, s) if regex.match(`^\s*static\s*\{\s*$`, s)

# `static` alone, with the brace on the next line.
_opens(lines, k, s) if {
	regex.match(`^\s*static\s*$`, s)
	k + 1 < count(lines)
	startswith(trim_space(lines[k + 1]), "{")
}

_constructs(code) if {
	some m in regex.find_all_string_submatch_n(`(\bthrow\s+)?\bnew\s+([A-Za-z_][\w.]*)\s*(?:<(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*>)?\s*\(`, code, -1)
	m[1] == ""
	parts := split(m[2], ".")
	t := parts[count(parts) - 1]
	not _benign[t]
	not endswith(t, "Exception")
	not endswith(t, "Error")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`(?m)^\s*static\s*(\{|$)`, content)
	contains(content, "new ")
	lines := split(content, "\n")
	some k, sl in lines
	startswith(trim_space(sl), "static")
	b := _block(lines, k)
	some i in numbers.range(b[0], b[1])
	line := lines[i]
	contains(line, "new ")
	not helpers.is_comment_line(line)
	_constructs(_strip(line))
	finding := {
		"rule_id": metadata.id,
		"message": "Object constructed inside a static initializer: it is created at class-load time, before configuration, and a failure becomes ExceptionInInitializerError; create it lazily or inject it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
