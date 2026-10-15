# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1073

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1073",
	"name": "Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses",
	"description": "A Java method with a body that performs five or more data-resource accesses itself: JDBC executeQuery/executeUpdate/executeLargeUpdate/executeBatch and execute() on a statement, JdbcTemplate query*/update/batchUpdate/execute, JPA createQuery/createNativeQuery/createNamedQuery and EntityManager find/persist/merge/remove/refresh/getReference, Spring Data repository find*/save*/delete*/exists*/count* calls, and Hibernate Session / MyBatis SqlSession get/load/save/saveOrUpdate/persist/merge/update/delete/selectOne/selectList/insert calls on a receiver named *session. A method that makes that many round trips to the database is hard to keep transactional and slow under load; move the work into one query, a stored procedure or a dedicated data-access method. The finding is on the method declaration. Methods are recognised by a modifier, or for package-private methods by a return type, name, parameter list and opening brace on one line. Not reported: fewer than five accesses in one method (accesses spread over several methods are counted per method), statements prepared once and run as one batch, abstract and interface methods, test sources, and calls in comments. The method boundary is the next method declaration (at most 200 lines), so an anonymous class inside a method is counted with it, and a package-private method whose signature spans lines is counted with the method above it.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1073/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1073],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["excessive-data-access", "cwe-1073"],
}

_threshold := 5

_access_re := concat("|", [
	`\.\s*(?:executeQuery|executeUpdate|executeLargeUpdate|executeBatch|executeLargeBatch)\s*\(`,
	`(?i:\b(?:\w*stmt|\w*statement|ps\w*|st)\s*\.\s*execute\s*\()`,
	`(?i:\b\w*jdbc\w*\s*\.\s*(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|batchUpdate|execute)\s*\()`,
	`\.\s*(?:createQuery|createNativeQuery|createNamedQuery)\s*\(`,
	`(?i:\b\w*entityManager\s*\.\s*(?:find|persist|merge|remove|refresh|getReference)\s*\()`,
	`\bem\s*\.\s*(?:find|persist|merge|remove|refresh|getReference)\s*\(`,
	`\b\w+Repository\s*\.\s*(?:find\w*|save\w*|delete\w*|exists\w*|count\w*|getById|getReferenceById)\s*\(`,
	`(?i:\b\w*session\s*\.\s*(?:get|load|save|saveOrUpdate|persist|merge|update|delete|remove|refresh|createCriteria|selectOne|selectList|selectMap|insert)\s*\()`,
])

# A method or constructor declaration with at least one modifier whose
# parameter list opens on this line and that is not terminated by `;`.
_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|default)\s+)+(?:<[^>]+>\s+)?(?:[\w.$]+(?:\s*<[^;]*?>)?(?:\[\])*\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*$`

_keywords := {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "class", "interface", "enum", "record"}

_is_decl(line) if {
	m := regex.find_all_string_submatch_n(_decl_re, line, 1)[0]
	not _keywords[m[1]]
	not contains(line, " class ")
	not regex.match(`=\s*new\b|\)\s*;\s*$|->`, line)
}

# A package-private method has no modifier, so it is recognised by its shape
# instead: a return type, a name, the parameter list and the opening brace on
# one line (optionally after a throws clause). Without it, the accesses of such
# a method would be counted for the method declared above it.
_bare_decl_re := `^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:<[^>]+>\s+)?([\w.$]+)(?:\s*<[^;{}]*?>)?(?:\[\])*\s+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*$`

_type_keywords := {"else", "return", "new", "throw", "case", "package", "import", "yield"}

_is_decl(line) if {
	m := regex.find_all_string_submatch_n(_bare_decl_re, line, 1)[0]
	not _type_keywords[m[1]]
	not _keywords[m[2]]
	not regex.match(`=|->`, line)
}

_end(decls, j, n, _) := decls[j + 1] if j + 1 < count(decls)

_end(decls, j, n, d) := min([n, d + 200]) if j + 1 >= count(decls)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	count(regex.find_all_string_submatch_n(_access_re, content, -1)) >= _threshold
	lines := split(content, "\n")
	decls := [i | some i, line in lines; contains(line, "("); _is_decl(line)]
	some j, d in decls
	end := _end(decls, j, count(lines), d)
	body := concat("\n", [l | some l in array.slice(lines, d + 1, end); not helpers.is_comment_line(l)])
	n := count(regex.find_all_string_submatch_n(_access_re, body, -1))
	n >= _threshold
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Method performs %d data-resource accesses; combine them into fewer queries or move them into a dedicated data-access operation", [n]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d + 1,
		"snippet": lines[d],
	}
}
