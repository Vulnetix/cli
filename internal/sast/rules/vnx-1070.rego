# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1070

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1070",
	"name": "Serializable Data Element Containing non-Serializable Item Elements",
	"description": "An instance field of a JDK type that is never serializable (Thread, Socket and socket channels, Input/OutputStream, Reader/Writer and their common subclasses, JDBC Connection/Statement/ResultSet/DataSource, EntityManager, ExecutorService/Executor, Optional and Stream, Logger, HttpClient, URLConnection, Process, ClassLoader), declared with an access modifier (after any annotations, one or several names) and neither static nor transient, inside a Java class whose own header implements Serializable (the nearest enclosing class declaration). Serialising such an object throws NotSerializableException at run time, or silently loses the resource when a custom writeObject skips it. Not reported: static and transient fields, fields of another class in the same file that is not Serializable, a class that is Serializable only through a superclass (cross-file), a simple name imported from a non-JDK package (com.acme.Process, org.slf4j.Logger, Guava Optional), the JDBC names (Connection, Statement, ResultSet, DataSource) in a file that never mentions java.sql or javax.sql (a bank Statement or graph Connection), local variables, package-private fields with no modifier (a documented gap), and comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1070/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1070],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["serializable-data-element", "cwe-1070"],
}

_types := concat("|", [
	"Thread", "Socket", "ServerSocket", "DatagramSocket", "SocketChannel", "ServerSocketChannel", "Selector",
	"InputStream", "OutputStream", "FileInputStream", "FileOutputStream", "BufferedInputStream",
	"BufferedOutputStream", "ObjectInputStream", "ObjectOutputStream", "PrintStream", "Reader", "Writer",
	"BufferedReader", "BufferedWriter", "InputStreamReader", "OutputStreamWriter", "FileReader", "FileWriter",
	"PrintWriter", "Scanner", "Connection", "Statement", "PreparedStatement", "CallableStatement", "ResultSet",
	"DataSource", "EntityManager", "ExecutorService", "ScheduledExecutorService", "Executor", "Optional",
	"OptionalInt", "OptionalLong", "OptionalDouble", "Stream", "IntStream", "LongStream", "Logger",
	"HttpClient", "HttpURLConnection", "URLConnection", "Process", "ClassLoader",
])

# A field declaration: optional annotations, modifiers drawn only from
# access/final/volatile (so a static or transient field cannot match), then a
# non-serializable type (optionally package-qualified), one or more names, an
# optional initialiser and the closing semicolon.
_field_re := concat("", [
	`^(\s*)(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:public|protected|private|final|volatile)\s+)+)(?:([\w.]+)\.)?(`,
	_types,
	`)\b(?:\s*<[^;=]*>)?\s+[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*\s*(?:=[^;]*)?;\s*(?://.*)?$`,
])

# Names that are as often a project's own class (a bank Statement, a graph
# Connection) as the JDBC type: they count only when the file uses java.sql /
# javax.sql or the field spells the package.
_jdbc := {"Connection", "Statement", "PreparedStatement", "CallableStatement", "ResultSet", "DataSource"}

_jdk_type(content, qual, type) if {
	qual != ""
	regex.match(`^(java|javax|jakarta)\.`, qual)
}

_jdk_type(content, qual, type) if {
	qual == ""
	not _jdbc[type]
	not _imported_elsewhere(content, type)
}

_jdk_type(content, qual, type) if {
	qual == ""
	_jdbc[type]
	regex.match(`\bjavax?\.sql\b`, content)
	not _imported_elsewhere(content, type)
}

# The simple name is imported from a package outside the JDK: a project or
# library type whose serializability one file cannot tell.
_imported_elsewhere(content, type) if {
	some m in regex.find_all_string_submatch_n(concat("", [`(?m)^\s*import\s+([\w.]+)\.`, type, `\s*;`]), content, -1)
	not regex.match(`^(java|javax|jakarta)\.`, m[1])
}

_indent(s) := count(regex.find_all_string_submatch_n(`^[ \t]*`, s, 1)[0][0])

_class_header_re := `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed|strictfp)\s+)*(?:class|enum|record)\s+[A-Za-z_$]`

# The class that declares the field: the nearest class header above it at a
# shallower indentation. Its header (up to the opening brace, at most three
# lines) must implement Serializable.
_enclosing_serializable(lines, i, indent) if {
	lo := max([0, i - 400])
	hs := [k | some k in numbers.range(lo, i - 1); regex.match(_class_header_re, lines[k]); _indent(lines[k]) < indent]
	count(hs) > 0
	h := hs[count(hs) - 1]
	header := concat(" ", array.slice(lines, h, min([h + 3, count(lines)])))
	regex.match(`^[^{]*\bimplements\b[^{]*\bSerializable\b`, header)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\bimplements\b[^{;]*\bSerializable\b`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ";")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_field_re, line, 1)[0]
	regex.match(`\b(public|protected|private)\b`, m[2])
	_jdk_type(content, m[3], m[4])
	_enclosing_serializable(lines, i, count(m[1]))
	finding := {
		"rule_id": metadata.id,
		"message": "Serializable class holds a non-serializable field; mark it transient (and restore it in readObject) or remove it from the serialised state",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
