# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1043

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1043",
	"name": "Data Element Aggregating an Excessively Large Number of Non-Primitive Elements",
	"description": "A class, struct or interface that holds more than 10 instance fields of non-primitive type, the CISQ maintainability measure behind CWE-1043: an object that aggregates that many other objects is hard to audit for what it exposes, serialises or retains. Reported once, on the declaration line: a Java class (including one whose extends/implements list wraps before the brace), a Go struct type, a Python class (dataclass, pydantic, attrs or any class with annotated class-level fields) and a TypeScript class, interface or object type alias, counting only fields declared directly in that body. A field is non-primitive when its type names anything other than a primitive or value type (numbers, booleans, strings, bytes, dates, times, durations, UUIDs, BigDecimal and the boxed types, error, any/unknown), so List<Order>, map[string]*Session, Optional[Cart], Role[] and the Python forward reference Mapped[\"Customer\"] count while List<String>, []byte, dict[str, str], Mapped[int], Literal[\"a\", \"b\"] and 'light' | 'dark' do not. Python fields assigned without an annotation (Django models.ForeignKey(...), self.x = ... in __init__) and TypeScript constructor parameter properties are not counted. Not reported: static fields and constants, ClassVar, fields of nested classes (counted for the nested class), method parameters, enums and records, plain JavaScript, generated code (Code generated ... DO NOT EDIT, @Generated), test code and comments. CISQ suggests 5 as a threshold; this rule uses 10 so that it reports only the outliers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1043/",
	"languages": ["java", "python", "node", "go"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1043],
	"capec": ["CAPEC-130"],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["data-aggregation", "excessive-fields", "code-quality", "cwe-1043"],
}

_limit := 10

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "ts" if {
	some ext in {".ts", ".tsx", ".mts", ".cts"}
	endswith(path, ext)
	not endswith(path, ".d.ts")
}

_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)src/(test|it)/`, path)

_generated(content) if {
	contains(content, "Code generated")
	contains(content, "DO NOT EDIT")
}

_generated(content) if contains(content, "@Generated")

_generated(content) if contains(content, "@generated")

_file_needles := {
	"java": {"class "},
	"go": {" struct"},
	"py": {"class "},
	"ts": {"class ", "interface ", "type "},
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

# ── Declarations: (regex for the declaration line) ──────────────────────

_decl_re := {
	"java": `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|abstract|final|static|sealed|non-sealed|strictfp)\s+)*class\s+\w+[^;{]*\{\s*$`,
	"go": `^type\s+\w+(?:\[[^\]]*\])?\s+struct\s*\{\s*$`,
	"py": `^\s*class\s+\w+\s*(?:\([^)]*\))?\s*:\s*(?:#.*)?$`,
	"ts": `^\s*(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:(?:class|interface)\s+[\w$]+[^{=;]*\{|type\s+[\w$]+(?:<[^=]*>)?\s*=\s*\{)\s*$`,
}

_decl_needle := {"java": {"class"}, "go": {"struct"}, "py": {"class"}, "ts": {"class", "interface", "type"}}

# The body closes at the first later line at the declaration's indentation
# (a closing brace, or for Python any code line); at most 600 lines are
# read. The closing line is found by a substring search over the joined
# lines, not by testing each line.
_close_pos(rest, line, lang) := indexof(rest, concat("", ["\n", substring(line, 0, _indent(line)), "}"])) if lang != "py"

_close_pos(rest, line, "py") := indexof(rest, m) if {
	some m in regex.find_n(sprintf("\n[ \t]{0,%d}[^\\s#]", [_indent(line)]), rest, 1)
}

_close_pos(rest, line, "py") := -1 if {
	count(regex.find_n(sprintf("\n[ \t]{0,%d}[^\\s#]", [_indent(line)]), rest, 1)) == 0
}

_body_end(lines, i, line, lang) := e if {
	rest := concat("", ["\n", concat("\n", array.slice(lines, i + 1, i + 601))])
	pos := _close_pos(rest, line, lang)
	pos >= 0
	e := i + 1 + count(indexof_n(substring(rest, 0, pos), "\n"))
}

_body_end(lines, i, line, lang) := min([i + 601, count(lines)]) if {
	rest := concat("", ["\n", concat("\n", array.slice(lines, i + 1, i + 601))])
	_close_pos(rest, line, lang) < 0
}

# ── Fields: names and type at the body's own indentation ────────────────

_field_re := {
	"java": `^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*((?:(?:private|protected|public|final|transient|volatile|static)\s+)*)([A-Za-z_][\w.]*(?:\s*<.*>)?(?:\s*\[\s*\])*)\s+([a-zA-Z_]\w*)\s*(?:=.*)?;\s*(?://.*)?$`,
	"py": `^\s*()([A-Za-z_]\w*)\s*:\s*([^=#]+?)\s*(?:=.*)?(?:#.*)?$`,
	"ts": `^\s*((?:(?:public|private|protected|readonly|static|declare|override)\s+)*)([A-Za-z_$][\w$]*)[?!]?\s*:\s*(.+?)\s*[;,]?\s*(?://.*)?$`,
}

# Number of non-primitive fields on one line ([] when it is not a field).
_fields(line, "java") := [1 |
	some m in regex.find_all_string_submatch_n(_field_re.java, line, 1)
	not contains(m[1], "static")
	not m[2] in {"return", "throw", "package", "import", "else", "new", "yield"}
	_nonprim(m[2], "java")
]

_fields(line, "py") := [1 |
	some m in regex.find_all_string_submatch_n(_field_re.py, line, 1)
	not m[2] in {"else", "try", "finally", "except", "lambda", "return", "case", "match", "with", "for", "while", "if", "elif"}
	not contains(m[3], "ClassVar")
	not contains(m[3], "(")
	_nonprim(m[3], "py")
]

_fields(line, "ts") := [1 |
	some m in regex.find_all_string_submatch_n(_field_re.ts, line, 1)
	not contains(m[1], "static")
	not contains(m[3], "{")
	_nonprim(m[3], "ts")
]

# Go: `a, b *T`, `name T` and an embedded `*T` / `pkg.T`.
_fields(line, "go") := [1 |
	some m in regex.find_all_string_submatch_n("^\\t([A-Za-z_]\\w*(?:\\s*,\\s*[A-Za-z_]\\w*)*)\\s+([^\\s/`][^`]*?)\\s*(?:`[^`]*`)?\\s*(?://.*)?$", line, 1)
	_nonprim(m[2], "go")
	some _ in split(m[1], ",")
] if not regex.match("^\\t\\*?[A-Za-z_][\\w.]*\\s*(?:`[^`]*`)?\\s*(?://.*)?$", line)

_fields(line, "go") := [1] if regex.match("^\\t\\*?[A-Za-z_][\\w.]*\\s*(?:`[^`]*`)?\\s*(?://.*)?$", line)

# Every field line of the language carries this character.
_field_mark := {"java": ";", "go": "\t", "py": ":", "ts": ":"}

_prim := {
	"java": {
		"byte", "short", "int", "long", "float", "double", "boolean", "char", "var",
		"String", "CharSequence", "Integer", "Long", "Short", "Byte", "Character", "Double", "Float", "Boolean", "Number",
		"BigDecimal", "BigInteger", "UUID", "Instant", "LocalDate", "LocalDateTime", "LocalTime", "OffsetDateTime",
		"ZonedDateTime", "Date", "Duration", "Period", "AtomicInteger", "AtomicLong", "AtomicBoolean",
		"List", "Set", "Map", "Collection", "Optional", "ArrayList", "LinkedList", "HashMap", "TreeMap", "HashSet",
		"LinkedHashMap", "LinkedHashSet", "TreeSet", "Queue", "Deque", "Iterable", "SortedMap", "SortedSet",
		"ConcurrentHashMap", "ConcurrentMap", "EnumSet", "EnumMap", "extends", "super",
	},
	"go": {
		"string", "bool", "byte", "rune", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
		"uint32", "uint64", "uintptr", "float32", "float64", "complex64", "complex128", "error", "any",
		"interface", "struct", "map", "chan", "time.Time", "time.Duration", "atomic.Bool", "atomic.Int32",
		"atomic.Int64", "atomic.Uint32", "atomic.Uint64",
	},
	"py": {
		"str", "int", "float", "bool", "bytes", "complex", "None", "Any", "Decimal", "datetime", "date", "time",
		"timedelta", "UUID", "Optional", "list", "dict", "set", "frozenset", "tuple", "List", "Dict", "Set",
		"FrozenSet", "Tuple", "Union", "Literal", "Sequence", "Mapping", "Iterable", "Final", "Annotated",
		"datetime.datetime", "datetime.date", "uuid.UUID", "typing.Optional", "typing.Any", "S", "Mapped",
	},
	"ts": {
		"string", "number", "boolean", "bigint", "symbol", "any", "unknown", "null", "undefined", "void", "never",
		"object", "Date", "Array", "ReadonlyArray", "Record", "Map", "Set", "Partial", "Readonly", "true", "false",
		"S",
	},
}

_strip_strings(s) := regex.replace(s, "\"[^\"]*\"|'[^']*'|`[^`]*`", "S")

# Python: a quoted name is a forward reference to a type ("Customer"),
# except inside Literal[...], where the strings are values.
_type_text(t, "py") := _strip_strings(t) if contains(t, "Literal")

_type_text(t, "py") := replace(replace(t, "\"", ""), "'", "") if not contains(t, "Literal")

_type_text(t, lang) := _strip_strings(t) if lang != "py"

_nonprim(t, lang) if {
	some m in regex.find_all_string_submatch_n(`[A-Za-z_$][\w$.]*`, _type_text(t, lang), -1)
	not m[0] in _prim[lang]
	not regex.match(`^\d`, m[0])
}

# ── Findings ─────────────────────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	some fn in _file_needles[lang]
	contains(content, fn)
	not _is_test(path)
	not _generated(content)
	lines := split(content, "\n")
	some i, line in lines
	some dn in _decl_needle[lang]
	contains(line, dn)
	not helpers.is_comment_line(line)
	s := _open_line(lines, i, line, lang)
	end := _body_end(lines, s, line, lang)
	bi := _body_indent(lines, s, end, lang)
	n := sum([c |
		some j in helpers.span(s + 1, end - 1)
		contains(lines[j], _field_mark[lang])
		_indent(lines[j]) == bi
		not helpers.is_comment_line(lines[j])
		c := count(_fields(lines[j], lang))
	])
	n > _limit
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This type declares %d fields of non-primitive type (more than %d), so one object aggregates that many other objects; split it into smaller types that group related fields, so each can be reviewed for what it exposes, serialises and retains", [n, _limit]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# The line that opens the body: the declaration itself, or for a Java
# declaration whose extends/implements list wraps, the first of the next
# four lines that ends with the opening brace.
_open_line(_, i, line, lang) := i if regex.match(_decl_re[lang], line)

_java_open_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|private|protected|abstract|final|static|sealed|non-sealed|strictfp)\s+)*class\s+\w+[^;{]*$`

_open_line(lines, i, line, "java") := k if {
	not regex.match(_decl_re.java, line)
	regex.match(_java_open_re, line)
	ks := [j |
		some j in numbers.range(i + 1, min([count(lines) - 1, i + 4]))
		endswith(trim_space(lines[j]), "{")
	]
	count(ks) > 0
	k := ks[0]
	every j in numbers.range(i + 1, k) {
		not contains(lines[j], ";")
		not contains(lines[j], "}")
	}
}

# Go fields are one tab in (gofmt); elsewhere the body's indentation is
# that of its first code line.
_body_indent(_, _, _, "go") := 1

_body_indent(lines, i, end, lang) := _indent(lines[j]) if {
	lang != "go"
	j := min({k |
		some k in helpers.span(i + 1, end - 1)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
	})
}
