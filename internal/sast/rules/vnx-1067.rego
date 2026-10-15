# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1067

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1067",
	"name": "Excessive Execution of Sequential Searches of Data Resource",
	"description": "Java: an SQL or JPQL search written so the database cannot use an index and must scan the table sequentially. Reported: a LIKE/ILIKE pattern with a leading wildcard in a query string (`LIKE '%...`, `LIKE CONCAT('%', :p ...)`, `ILIKE '%' || :p`), a value bound to a query parameter that starts with a wildcard (`ps.setString(1, \"%\" + q ...)`, `query.setParameter(\"n\", \"%\" + n)`, or a variable assigned `\"%\" + ...` up to 20 lines earlier and then bound), a function applied to a column in a comparison (`WHERE LOWER(col) = ...`, `UPPER(col) LIKE ...`), including in @Query annotations, Java text blocks and query strings split by concatenation; the JPA Criteria and Hibernate forms (`cb.like(root.get(\"n\"), \"%\" + q)`, `cb.equal(cb.lower(root.get(\"n\")), v)`, `MatchMode.ANYWHERE`/`END`); and Spring Data derived query methods in a Repository interface whose name compiles to the same thing (`findByNameContaining`, `...EndingWith`, `...IgnoreCase`). Not reported: trailing-wildcard (prefix) searches such as `LIKE 'adm%'`, `q + \"%\"` or `findByNameStartingWith`, a function applied to the bound value rather than the column (`col = LOWER(:v)`), functions in a SELECT list, GROUP BY or ORDER BY, plain equality, `%` in format strings and log text, and comments. Whether the column is indexed, or the table small, is not known: review each finding against the schema (use a full-text or trigram index, a functional index, or a normalised column).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1067/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1067],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["sequential-search", "sql", "performance", "java", "cwe-1067"],
}

_literals(line) := [m[1] | some m in regex.find_all_string_submatch_n(`"((?:[^"\\]|\\.)*)"`, line, -1)]

# LIKE '%x', ILIKE '%x', LIKE CONCAT('%', :p), LIKE '%' || :p
_unindexable(lit) if regex.match(`(?i)\bI?LIKE\s+(?:CONCAT\s*\(\s*)?'%`, lit)

# WHERE LOWER(col) = ..., UPPER(col) LIKE ...
_unindexable(lit) if regex.match(`(?i)(?:^|\b(?:WHERE|AND|OR|ON)\s+|\(\s*)(?:LOWER|UPPER|TRIM|LTRIM|RTRIM|SUBSTR|SUBSTRING|DATE|YEAR|MONTH|CAST|COALESCE)\s*\(\s*[A-Za-z_][\w.]*\s*(?:,[^)]*)?\)\s*(?:=|<>|!=|>=|<=|<|>|\bI?LIKE\b|\bIN\b|\bBETWEEN\b)`, lit)

_sql_kw := `(?i)\b(?:SELECT|UPDATE|DELETE|FROM|WHERE|JOIN)\b`

_sink(_, _, line, _) if {
	some lit in _literals(line)
	_unindexable(lit)
	_query_text(line, lit)
}

# The literal is SQL/JPQL, or a fragment of a query concatenated across lines.
_query_text(_, lit) if regex.match(_sql_kw, lit)

_query_text(line, _) if regex.match(`^\s*(?:\+\s*)?"`, line)

_wild_value := `(?:"%"\s*\+|String\.format\s*\(\s*"%%|"%"\s*\.concat\s*\()`

_binder := `\.(?:setString|setNString|setObject|setParameter|bind|addValue)\s*\(\s*[^,]+,\s*`

# ps.setString(1, "%" + q ...), query.setParameter("n", "%" + n)
_sink(_, _, line, _) if regex.match(concat("", [_binder, _wild_value]), line)

# JPA Criteria / Hibernate: cb.like(root.get("n"), "%" + q), cb.equal(cb.lower(root.get("n")), v),
# Restrictions.like("n", q, MatchMode.ANYWHERE)
_sink(_, _, line, _) if regex.match(concat("", [`\.(?:like|ilike|notLike)\s*\(\s*[^,]+,\s*`, _wild_value]), line)

_sink(_, _, line, _) if regex.match(`\.(?:equal|notEqual|like|notLike|ilike|in)\s*\(\s*\w+\s*\.\s*(?:lower|upper|trim|substring)\s*\(`, line)

_sink(_, _, line, _) if regex.match(`\bMatchMode\s*\.\s*(?:ANYWHERE|END)\b`, line)

# String pattern = "%" + term + "%"; ... ps.setString(1, pattern);
_sink(lines, i, line, wild) if {
	some v in wild
	regex.match(concat("", [`(?:`, _binder, `|\.(?:like|ilike)\s*\(\s*[^,]+,\s*)`, v, `\s*\)`]), line)
	some k in numbers.range(max([0, i - 20]), i - 1)
	regex.match(concat("", [`\b`, v, `\s*=\s*`, _wild_value]), lines[k])
}

# A line inside a Java text block (""" ... """) of query text.
_sink(lines, i, line, _) if {
	not contains(line, "\"")
	_unindexable(line)
	opens := [k |
		some k in numbers.range(max([0, i - 30]), i - 1)
		contains(lines[k], `"""`)
	]
	count(opens) > 0
	o := max(opens)
	regex.match(`"""\s*$`, lines[o])
	not regex.match(`^\s*"""`, lines[o])
	regex.match(_sql_kw, concat("\n", array.slice(lines, o, i + 1)))
}

_wild_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*(?:"%"\s*\+|String\.format\s*\(\s*"%%|"%"\s*\.concat\s*\()`, content, -1)
}

_gate := `(?i)(?:\bI?LIKE\b|\b(?:LOWER|UPPER|TRIM|LTRIM|RTRIM|SUBSTR|SUBSTRING|DATE|YEAR|MONTH|CAST|COALESCE)\s*\(|MatchMode)`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_gate, content)
	regex.match(`(?i)(?:\bSELECT\b|\bWHERE\b|\bLIKE\b|@Query|createQuery|prepareStatement|CriteriaBuilder|Restrictions)`, content)
	wild := _wild_vars(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	_sink(lines, i, line, wild)
	finding := {
		"rule_id": metadata.id,
		"message": "Search the database cannot answer from an index (leading LIKE wildcard or a function on the column): every call scans the table; use a full-text/trigram or functional index, or a prefix search",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Spring Data derived queries whose name asks for a contains/suffix match or
# a case-insensitive comparison: findByNameContaining -> LIKE '%x%',
# findByEmailEndingWith -> LIKE '%x', ...IgnoreCase -> UPPER(col) = UPPER(?).
_derived_re := `^\s*(?:(?:public|default|abstract)\s+)?[\w.<>\[\], ?]+\s+(?:find|read|get|query|search|stream|count|exists|delete|remove)\w*?By\w*?(?:Containing|Contains|EndingWith|EndsWith|IgnoreCase|IgnoringCase)\w*\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`\binterface\s+\w+[^{]*\b(?:Jpa|Crud|PagingAndSorting|ListCrud|Mongo|Reactive\w*)?Repository\b`, content)
	regex.match(`By\w*(?:Containing|Contains|EndingWith|EndsWith|IgnoreCase|IgnoringCase)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "By")
	not helpers.is_comment_line(line)
	regex.match(_derived_re, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Derived repository query that compiles to a leading-wildcard LIKE or a function on the column (Containing/EndingWith/IgnoreCase): every call scans the table; use a full-text/trigram or functional index, or a prefix search",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
