# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_395

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-395",
	"name": "Use of NullPointerException Catch to Detect NULL Pointer Dereference",
	"description": "A catch clause catches the null-dereference exception itself, using it in place of a null check: Java catch (NullPointerException e), including final, the fully qualified java.lang name and a multi-catch (A | NullPointerException e); Kotlin catch (e: NullPointerException) and catch (e: KotlinNullPointerException); C# catch (NullReferenceException) with or without a variable, including System.NullReferenceException, with or without a when filter, and catch (Exception ex) when (ex is NullReferenceException); a Java catch clause whose parenthesis opens at the end of the line is joined with the next two lines. Catching it hides which reference was null and also swallows NPEs thrown by unrelated bugs deeper in the call. Not reported: throwing NullPointerException, Objects.requireNonNull, assertThrows(NullPointerException.class, ...), instanceof tests, class names that merely contain the word (NullPointerExceptionMapper), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-395/",
	"languages": ["java", "kotlin", "csharp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [395],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["error-handling", "cwe-395"],
}

_lang_re(path) := `\bcatch\s*\(\s*(?:final\s+)?(?:[\w.]+\s*\|\s*)*(?:java\.lang\.)?NullPointerException(?:\s*\|\s*[\w.]+)*\s+\w+\s*\)` if endswith(path, ".java")

_lang_re(path) := `\bcatch\s*\(\s*\w+\s*:\s*(?:java\.lang\.|kotlin\.)?(?:Kotlin)?NullPointerException\s*\)` if endswith(path, ".kt")

_lang_re(path) := `\bcatch\s*\(\s*(?:System\.)?NullReferenceException(?:\s+\w+)?\s*\)|\bcatch\s*\([^)]*\)\s*when\s*\([^)]*\bis\s+(?:System\.)?NullReferenceException\b` if endswith(path, ".cs")

_lang_re(path) := `\bcatch\s*\(\s*\w+\s*:\s*(?:java\.lang\.|kotlin\.)?(?:Kotlin)?NullPointerException\s*\)` if endswith(path, ".kts")

# Remove string literals so a quoted catch clause does not match.
_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

# The catch clause, joined with the next two lines when its parenthesis is
# opened and left open on this line: catch (\n NullPointerException e\n).
_clause(lines, i, line) := concat(" ", array.slice(lines, i, i + 3)) if {
	regex.match(`\bcatch\s*\(\s*$`, line)
} else := line

findings contains finding if {
	some path, content in input.file_contents
	re := _lang_re(path)
	regex.match(`Null(?:Pointer|Reference)Exception`, content)
	not helpers.is_test_path(path)
	not regex.match(`(?:^|/)[^/]*Tests?\.(?:kt|cs)$`, path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "catch")
	not helpers.is_comment_line(line)
	regex.match(re, _strip_strings(_clause(lines, i, line)))
	finding := {
		"rule_id": metadata.id,
		"message": "Null dereference handled by catching the null-pointer exception: check the reference for null (or use Optional/?./??) instead, so unrelated null bugs are not swallowed",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
