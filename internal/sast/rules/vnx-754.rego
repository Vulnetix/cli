# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_754

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-754",
	"name": "Class resource used without checking for null",
	"description": "Java's Class/ClassLoader.getResourceAsStream() and ServletContext.getResourceAsStream() return null, rather than throwing, when the resource is missing (a packaging change, a renamed file, a different class loader), and Class/ClassLoader.getResource() does the same; using the result unchecked turns that unusual condition into a NullPointerException far from its cause. Reported: the call's result dereferenced in the same expression (getResourceAsStream(...).readAllBytes(), getClass().getResource(...).toURI()/getFile()/getPath()/openStream()); passed straight into a consumer that dereferences it (Properties.load(...), new InputStreamReader/BufferedInputStream/Scanner/ObjectInputStream(...), IOUtils.toString/toByteArray/copy, ImageIO.read, Files.copy, a parser's parse/readTree/readValue), on the same line or with the consumer opening on the line above; and the result assigned to a variable that one of the next 15 lines dereferences or passes to such a consumer before any null check of it. Not reported: a result checked with == null/!= null, Objects.requireNonNull, Optional.ofNullable, Preconditions.checkNotNull or Assert.notNull before use; Spring ResourceLoader.getResource(), which never returns null; test code, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-754/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [754],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unchecked-conditions", "null-dereference", "cwe-754"],
}

_code(line) := regex.replace(line, `"(\\.|[^"\\])*"`, `""`)

# The nullable call: getResourceAsStream on any receiver; getResource only on
# a Class or ClassLoader (Spring's ResourceLoader.getResource never returns null).
_call := `(?:\bgetResourceAsStream|(?:\bgetClass\(\)|\.class|[Cc]lass[Ll]oader\(\)|\b[a-z]\w*[Cc]lass[Ll]oader|\bClassLoader\.getSystem)\s*\.\s*getResource|\bgetSystemResourceAsStream|\bgetSystemResource)\s*\(\s*(?:[^()]|\([^()]*\))*\)`

_chained_re := concat("", [_call, `\s*\.\s*\w+\s*\(`])

_consumer := `(?:\.load|\.loadFromXML|new\s+(?:InputStreamReader|BufferedInputStream|BufferedReader|Scanner|DataInputStream|ObjectInputStream|GZIPInputStream|ZipInputStream|JarInputStream|PushbackInputStream)|IOUtils\.(?:toString|toByteArray|copy|readLines|readFully)|ImageIO\.read|Files\.copy|(?:StreamUtils|FileCopyUtils|ByteStreams|CharStreams)\.\w+|\.readTree|\.readValue|\.parse|new\s+ImageIcon|Toolkit\.getDefaultToolkit\(\)\.getImage)\s*\(`

_nested_re := concat("", [_consumer, `\s*[\w.()]*?`, _call])

_guard := `(?:Objects\.requireNonNull|Optional\.ofNullable|checkNotNull|Assert\.notNull|Validate\.notNull|requireNonNull)\s*\(`

_flag(_, _, code) if {
	regex.match(_chained_re, code)
	not regex.match(_guard, code)
}

_flag(_, _, code) if {
	regex.match(_nested_re, code)
	not regex.match(_guard, code)
}

# props.load(
#     getClass().getResourceAsStream("x"));
_flag(lines, i, code) if {
	regex.match(concat("", [`^\s*[\w.()]*?`, _call]), code)
	i > 0
	prev := _code(lines[i - 1])
	regex.match(concat("", [_consumer, `\s*$`]), prev)
	not regex.match(_guard, prev)
}

# InputStream in = X.class.getResourceAsStream("x");  ... in.read()
_flag(lines, i, code) if {
	m := regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*=\s*(?:\([\w.]+\)\s*)?[\w.()]*?`, _call, `\s*[;)]`]), code, 1)
	count(m) > 0
	v := m[0][1]
	not contains(code, "null")
	not regex.match(_guard, code)
	end := min([count(lines) - 1, i + 15])
	i + 1 <= end
	uses := [k |
		some k in numbers.range(i + 1, end)
		not helpers.is_comment_line(lines[k])
		_uses(_code(lines[k]), v)
	]
	count(uses) > 0
	first := min(uses)
	not _checked(lines, i, first, v)
}

_uses(l, v) if regex.match(concat("", [`\b`, v, `\s*\.\s*\w+\s*\(`]), l)

_uses(l, v) if regex.match(concat("", [_consumer, `\s*`, v, `\s*[,)]`]), l)

_checked(lines, i, first, v) if {
	some k in numbers.range(i, first)
	l := lines[k]
	regex.match(concat("", [`\b`, v, `\s*[!=]=\s*null|\bnull\s*[!=]=\s*`, v, `\b|`, _guard, `\s*`, v, `\b|Objects\.(isNull|nonNull)\s*\(\s*`, v]), l)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "getResource")
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "getResource")
	not helpers.is_comment_line(line)
	code := _code(line)
	_flag(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": "getResourceAsStream()/getResource() returns null when the resource is missing, and the result is used without a null check. Check it (or Objects.requireNonNull it with a message naming the resource) before use",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
