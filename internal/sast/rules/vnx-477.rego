# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_477

import rego.v1

metadata := {
	"id": "VNX-477",
	"name": "Use of Obsolete Function",
	"description": "Reports calls to, and imports of, standard-library APIs that the platform has deprecated (most of them for removal) or already removed, each with its replacement. Java: Thread.stop/suspend/resume/countStackFrames, runFinalizersOnExit, the boxed-primitive constructors (new Integer(...), new Boolean(...)), one-argument URLEncoder.encode/URLDecoder.decode (platform charset), new Date(String) and Date.parse, Class.newInstance(), DataInputStream.readLine(), overriding finalize(), System.setSecurityManager and AccessController.doPrivileged, Character.isSpace/isJavaLetter, the BigDecimal.ROUND_* int constants. Python: the modules removed by PEP 594 and 632 (imp, asyncore, asynchat, smtpd, distutils, cgi, cgitb, pipes, telnetlib, crypt, nntplib, imghdr, sndhdr, audioop, uu, xdrlib, msilib, spwd, nis, ossaudiodev, mailcap, aifc, sunau, chunk), ssl.wrap_socket, platform.linux_distribution/dist, base64.encodestring/decodestring, cgi.escape, inspect.getargspec, os.tempnam/tmpnam, time.clock, logging.warn, sys.setcheckinterval, locale.format, unittest.makeSuite/findTestCases/getTestCaseNames, Element.getchildren/getiterator in a file that uses xml.etree (not lxml, which keeps them), collections.<ABC> without .abc, xml.etree.cElementTree, asyncio.async and @asyncio.coroutine, and the removed unittest aliases (assertEquals, assertNotEquals, assertItemsEqual, assertRegexpMatches, failUnless). Not reported: declarations marked @Deprecated or warnings.warn calls (they deprecate the project's own API, which is not use of an obsolete function), the supported replacements (URLEncoder.encode(s, UTF_8), Integer.valueOf, collections.abc, ssl.SSLContext.wrap_socket), names in strings and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-477/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [477],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["deprecated", "cwe-477"],
}

_arg := `(?:[^,()]|\((?:[^()]|\([^()]*\))*\))+`

_java := [
	{"re": `\b(?:Thread\.currentThread\(\)|\w*[Tt]hread\w*)\.(?:stop|suspend|resume|countStackFrames)\(\s*\)`, "msg": "Thread.stop/suspend/resume are unsafe and removed; signal the thread with interrupt() or a flag"},
	{"re": `\b(?:System|Runtime\.getRuntime\(\))\.runFinalizersOnExit\(`, "msg": "runFinalizersOnExit was removed; use try-with-resources or a shutdown hook"},
	{"re": `\bnew\s+(?:java\.lang\.)?(?:Integer|Long|Short|Byte|Double|Float|Boolean|Character)\s*\(`, "msg": "boxed-primitive constructors are deprecated for removal; use valueOf() or autoboxing"},
	{"re": concat("", [`\bURL(?:En|De)coder\.(?:encode|decode)\(\s*`, _arg, `\)`]), "msg": "one-argument URLEncoder.encode/URLDecoder.decode uses the platform charset and is deprecated; pass StandardCharsets.UTF_8"},
	{"re": `\bnew\s+Date\s*\(\s*"|\bDate\.parse\(`, "msg": "Date(String) and Date.parse are deprecated; use java.time parsing (Instant.parse, DateTimeFormatter)"},
	{"re": `\b(?:Class\.forName\([^)]*\)|\w+\.class|(?:clazz|klass|cls|\w*Class))\.newInstance\(\s*\)`, "msg": "Class.newInstance() is deprecated (it rethrows checked exceptions unchecked); use getDeclaredConstructor().newInstance()"},
	{"re": `\b(?:public|protected)\s+void\s+finalize\s*\(\s*\)`, "msg": "finalization is deprecated for removal; use Cleaner or try-with-resources"},
	{"re": `\bSystem\.setSecurityManager\(|\bAccessController\.doPrivileged\(`, "msg": "the Security Manager is deprecated for removal (JEP 411); it no longer enforces anything"},
	{"re": `\bCharacter\.(?:isSpace|isJavaLetter|isJavaLetterOrDigit)\(`, "msg": "Character.isSpace/isJavaLetter are deprecated; use isWhitespace/isJavaIdentifierStart/isJavaIdentifierPart"},
	{"re": `\bBigDecimal\.ROUND_(?:UP|DOWN|CEILING|FLOOR|HALF_UP|HALF_DOWN|HALF_EVEN|UNNECESSARY)\b`, "msg": "the BigDecimal.ROUND_* int constants are deprecated; pass a java.math.RoundingMode (RoundingMode.HALF_UP)"},
]

_py_removed := `imp|asyncore|asynchat|smtpd|distutils|cgi|cgitb|pipes|telnetlib|crypt|nntplib|imghdr|sndhdr|audioop|uu|xdrlib|msilib|spwd|nis|ossaudiodev|mailcap|aifc|sunau|chunk`

_py_abcs := `Mapping|MutableMapping|Sequence|MutableSequence|MutableSet|Iterable|Iterator|Callable|Hashable|Sized|Container|Generator|Awaitable|Coroutine|AsyncIterable|AsyncIterator|KeysView|ItemsView|ValuesView|MappingView`

_python := [
	{"re": concat("", [`^\s*(?:import\s+(?:`, _py_removed, `)\b(?:\.\w+)*\s*(?:$|,|\s+as\b|#)|from\s+(?:`, _py_removed, `)(?:\.\w+)*\s+import\b)`]), "msg": "this module was removed from the standard library (PEP 594 / PEP 632); use its documented replacement"},
	{"re": `\bssl\.wrap_socket\(`, "msg": "ssl.wrap_socket was removed in Python 3.12 and does not verify hostnames; use ssl.create_default_context().wrap_socket(..., server_hostname=...)"},
	{"re": `\bplatform\.(?:linux_distribution|dist)\(`, "msg": "platform.linux_distribution/dist were removed; use platform.freedesktop_os_release() or the distro package"},
	{"re": `\bbase64\.(?:encodestring|decodestring)\(`, "msg": "base64.encodestring/decodestring were removed; use encodebytes/decodebytes"},
	{"re": `\bcgi\.escape\(`, "msg": "cgi.escape was removed and did not escape quotes by default; use html.escape"},
	{"re": `\binspect\.getargspec\(`, "msg": "inspect.getargspec was removed; use inspect.signature or getfullargspec"},
	{"re": `\bos\.(?:tempnam|tmpnam)\(`, "msg": "os.tempnam/tmpnam were removed and are race-prone; use tempfile.mkstemp"},
	{"re": `\btime\.clock\(\s*\)`, "msg": "time.clock was removed; use time.perf_counter or time.process_time"},
	{"re": `\blogging\.warn\(`, "msg": "logging.warn is a deprecated alias; use logging.warning"},
	{"re": concat("", [`\bcollections\.(?:`, _py_abcs, `)\b|^\s*from\s+collections\s+import\s+(?:[\w\s,(]*\b)?(?:`, _py_abcs, `)\b`]), "msg": "the ABC aliases in collections were removed in Python 3.10; import them from collections.abc"},
	{"re": `\bxml\.etree\.cElementTree\b`, "msg": "xml.etree.cElementTree was removed; use xml.etree.ElementTree"},
	{"re": `\bsys\.(?:setcheckinterval|getcheckinterval)\(`, "msg": "sys.setcheckinterval was removed in Python 3.9; use sys.setswitchinterval"},
	{"re": `\blocale\.format\(`, "msg": "locale.format was removed in Python 3.12; use locale.format_string"},
	{"re": `\bunittest\.(?:makeSuite|findTestCases|getTestCaseNames)\(`, "msg": "unittest.makeSuite/findTestCases/getTestCaseNames were removed in Python 3.13; use unittest.TestLoader methods"},
	{"re": `\basyncio\.async\(|@asyncio\.coroutine\b`, "msg": "asyncio.async and @asyncio.coroutine were removed; use asyncio.ensure_future and async def"},
	{"re": `\.(?:assertEquals|assertNotEquals|assertItemsEqual|assertRegexpMatches|assertNotRegexpMatches|assertRaisesRegexp|assertAlmostEquals|assertNotAlmostEquals|failUnless|failIf|failUnlessEqual|failIfEqual)\(`, "msg": "this unittest alias was removed in Python 3.12; use the assertEqual/assertTrue/assertCountEqual/assertRegex spelling"},
]

_java_gate := `BigDecimal\.ROUND_|Thread|runFinalizersOnExit|new\s+(?:java\.lang\.)?(?:Integer|Long|Short|Byte|Double|Float|Boolean|Character)\s*\(|URL(?:En|De)coder|Date|newInstance|finalize|SecurityManager|doPrivileged|Character\.is`

_py_gate := concat("", [`(?m)^\s*(?:import|from)\s+(?:`, _py_removed, `)\b|ssl\.wrap_socket|platform\.(?:linux_distribution|dist)\(|base64\.(?:en|de)codestring|cgi\.escape|getargspec|sys\.[sg]etcheckinterval|locale\.format\(|unittest\.(?:makeSuite|findTestCases|getTestCaseNames)\(|os\.t(?:emp|mp)nam|time\.clock\(|logging\.warn\(|collections|cElementTree|asyncio\.(?:async\(|coroutine)|\.(?:assert\w*s|assertItemsEqual|assert\w*Regexp\w*|fail\w*)\(`])

# A literal's text is not code: blank it before matching.
_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_is_comment(line) if regex.match(`^\s*(?://|/\*|\*|#)`, line)

_hit(line, specs) := spec if {
	code := _strip_strings(line)
	matching := [s | some s in specs; regex.match(s.re, code)]
	count(matching) > 0
	spec := matching[0]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_java_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_java_gate, line)
	not _is_comment(line)
	spec := _hit(line, _java)
	finding := _finding(path, i, line, spec.msg)
}

# DataInputStream.readLine(): the variable must be declared as one in the file.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "DataInputStream")
	contains(content, ".readLine(")
	lines := split(content, "\n")
	names := {m[1] |
		some l in lines
		some m in regex.find_all_string_submatch_n(`\bDataInputStream\s+(\w+)\s*[=;,)]`, l, -1)
	}
	some i, line in lines
	contains(line, ".readLine(")
	not _is_comment(line)
	some v in names
	regex.match(concat("", [`\b`, v, `\.readLine\(\s*\)`]), _strip_strings(line))
	finding := _finding(path, i, line, "DataInputStream.readLine() does not convert bytes to characters and is deprecated; use BufferedReader.readLine()")
}

# A receiver declared in the file as a Thread or a Class (a parameter or a
# local): worker.suspend(), type.newInstance(). Same messages as the name-based
# entries, so a line both match is one finding.
_typed_receivers := [
	{"decl": `\bThread\s+(\w+)\s*[=;,)]`, "call": `\.(?:stop|suspend|resume|countStackFrames)\(\s*\)`, "msg": _java[0].msg},
	{"decl": `\bClass\s*(?:<[^>]*>)?\s+(\w+)\s*[=;,)]`, "call": `\.newInstance\(\s*\)`, "msg": _java[5].msg},
]

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\.(?:stop|suspend|resume|countStackFrames|newInstance)\(\s*\)`, content)
	lines := split(content, "\n")
	some spec in _typed_receivers
	names := {m[1] |
		some l in lines
		some m in regex.find_all_string_submatch_n(spec.decl, l, -1)
	}
	count(names) > 0
	some i, line in lines
	regex.match(spec.call, line)
	not _is_comment(line)
	some v in names
	regex.match(concat("", [`\b`, v, spec.call]), _strip_strings(line))
	finding := _finding(path, i, line, spec.msg)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_py_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	not _is_comment(line)
	spec := _hit(line, _python)
	not _in_docstring(lines, i)
	finding := _finding(path, i, line, spec.msg)
}

# Element.getchildren()/getiterator() were removed from xml.etree in Python 3.9
# (lxml still has them, and a project class may define its own), so only in a
# file that imports xml.etree and not lxml, and never on a def line.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "xml.etree")
	regex.match(`\.(?:getchildren|getiterator)\(`, content)
	not contains(content, "lxml")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.(?:getchildren|getiterator)\(`, _strip_strings(line))
	not _is_comment(line)
	not regex.match(`^\s*def\s`, line)
	not _in_docstring(lines, i)
	finding := _finding(path, i, line, "Element.getchildren()/getiterator() were removed from xml.etree in Python 3.9; use list(elem) and elem.iter()")
}

# An odd number of triple quotes above the line puts it inside a docstring or
# other triple-quoted literal. Only evaluated for a line that already matched.
_in_docstring(lines, i) if {
	above := concat("\n", array.slice(lines, 0, i))
	n := count(regex.find_all_string_submatch_n(`"""|'''`, above, -1))
	n % 2 == 1
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": sprintf("Obsolete API: %s", [msg]),
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
