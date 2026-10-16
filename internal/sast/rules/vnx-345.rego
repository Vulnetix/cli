# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_345

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-345",
	"name": "Insufficient Verification of Data Authenticity",
	"description": "Python code acts on data from an untrusted channel as though it were authentic, with no signature or digest check in between. Reported: (1) marshal.load()/loads() (through the module, an `import marshal as m` alias or `from marshal import loads`) applied to request data (Flask/Django/Starlette request body, form, args, cookies, files, headers), bytes read from a socket, or a body downloaded with requests/httpx get/post or urlopen() (a model or cache fetched from a server), inline (including an argument on the next lines) or through a variable assigned from it, possibly via one further assignment such as a base64 decode, within the 12 lines above; (2) exec()/eval() of content fetched over the network (requests/httpx get/post .text/.content, urlopen().read()), inline or through such a variable; (3) a file downloaded with urlretrieve() and then run with subprocess, os.system or os.exec*. Not reported: when the 15 lines above verify an HMAC or signature (hmac.compare_digest, hmac.new, itsdangerous Signer/unsign/loads with a serializer, .verify()), or a downloaded file's hash (hashlib, sha256, checksum, gpg); json.loads and ast.literal_eval; marshal of local files or of the program's own dumps(); comments and string literals. Unpickling untrusted bytes is the same weakness and is reported once, by its owner: pickle, cPickle, _pickle, dill, cloudpickle and jsonpickle calls by VNX-PY-003, and the loaders that unpickle under the hood (torch.load, joblib.load, pandas.read_pickle, numpy.load with allow_pickle=True) by VNX-PY-013, wherever the bytes come from.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-345/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [345],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["data-authenticity", "cwe-345", "deserialization", "python"],
}

_req_src_re := `\brequest\.(?:data|body|get_data|stream|files|form|args|values|cookies|COOKIES|json|get_json|POST|GET|FILES|headers|META|query_params)\b|\bself\.request\.(?:body|arguments|cookies|files)\b|\.recv(?:from|_into)?\(|\bawait\s+request\.(?:body|form|json)\(`

_fetch_src_re := `\b(?:requests|httpx|session|client)\.(?:get|post|request)\(|\burlopen\(|\bhttp\.request\(`

# Bytes a pickle may come from: the request, a socket, or an HTTP download (a
# model or cache fetched from a server). session.get() is not a fetch here:
# in Flask it is the signed session dictionary.
_deser_src_re := concat("|", [_req_src_re, `\b(?:requests|httpx)\.(?:get|post|request)\(|\burlopen\(`])

_verify_re :=`hmac\.compare_digest|hmac\.new\(|\bunsign\(|\bSigner\(|Serializer\(|\.verify\(|verify_signature|compare_digest`

_hash_re := `hashlib\.|sha256|sha512|checksum|\bgpg\b|verify_signature|\.verify\(`

# Only marshal is judged here. Every pickle-family call (pickle, cPickle,
# _pickle, dill, cloudpickle, jsonpickle) is reported by VNX-PY-003 and every
# loader that unpickles under the hood (torch.load, joblib.load,
# pandas.read_pickle, numpy.load(allow_pickle=True)) by VNX-PY-013, wherever
# the bytes come from; reporting them again here would show one problem twice.
_mods(content) := ms if {
	aliases := {m[1] |
		some m in regex.find_all_string_submatch_n(`(?m)^\s*import\s+marshal\s+as\s+([A-Za-z_]\w*)`, content, -1)
	}
	ms := {"marshal"} | aliases
}

_deser_re(content) := re if {
	alt := concat("|", sort(_mods(content)))
	re := concat("", [`\b(?:`, alt, `)\.loads?\s*\(`, _bare_loads(content)])
}

_bare_loads(content) := `|(?:^|[^.\w])loads\s*\(` if {
	regex.match(`(?m)^\s*from\s+marshal\s+import\s+[^\n]*\bloads\b`, content)
}

_bare_loads(content) := "" if {
	not regex.match(`(?m)^\s*from\s+marshal\s+import\s+[^\n]*\bloads\b`, content)
}

# Plain string literals are blanked; f-strings keep their text because they
# evaluate.
_code(line) := c if {
	a := regex.replace(line, `(^|[^fFrRbB\w"'])"(?:[^"\\]|\\.)*"`, `$1""`)
	c := regex.replace(a, `(^|[^fFrRbB\w"'])'(?:[^'\\]|\\.)*'`, `$1''`)
}

# The sink line and, for a call split over lines, its continuation.
_call_text(lines, i) := t if {
	endswith(trim_right(lines[i], " \t"), "(")
	t := concat(" ", array.slice(lines, i, min([count(lines), i + 4])))
}

_call_text(lines, i) := lines[i] if not endswith(trim_right(lines[i], " \t"), "(")

# Names assigned from src in the 12 lines above, plus one further hop.
_tainted(lines, i, src) := t0 | t1 if {
	t0 := helpers.tainted_names(lines, i, 12, src)
	t1 := {v |
		some j in numbers.range(max([0, i - 12]), i - 1)
		l := lines[j]
		not helpers.is_comment_line(l)
		some t in t0
		regex.match(concat("", [`\b`, t, `\b`]), l)
		v := helpers.assigned_first(l)
	}
}

_reaches(lines, i, text, src) if regex.match(src, _code(text))

_reaches(lines, i, text, src) if {
	some v in _tainted(lines, i, src)
	regex.match(concat("", [`\b`, v, `\b`]), _code(text))
}

_guarded(lines, i, re) if {
	w := helpers.code_window(lines, i, 15, 0)
	regex.match(re, w)
}

# (1) deserialisation of request or socket data
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "marshal")
	regex.match(`request|recv|urlopen|httpx`, content)
	sink := _deser_re(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(sink, _code(line))
	not helpers.is_comment_line(line)
	not regex.match(`\.dumps?\(`, line)
	_reaches(lines, i, _call_text(lines, i), _deser_src_re)
	not _guarded(lines, i, _verify_re)
	finding := _finding(path, i, line, "Untrusted request, socket or downloaded bytes are loaded with marshal with no signature check: marshal builds code objects, and whoever controls the bytes controls what this process runs. Use a data format (JSON) or verify an HMAC over the bytes before loading them")
}

# (2) exec/eval of content fetched over the network
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\b(?:exec|eval)\s*\(`, content)
	regex.match(`requests|httpx|urlopen|http\.request`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?:^|[^.\w])(?:exec|eval)\s*\(`, _code(line))
	not helpers.is_comment_line(line)
	_reaches(lines, i, _call_text(lines, i), _fetch_src_re)
	not _guarded(lines, i, _hash_re)
	finding := _finding(path, i, line, "Code downloaded over the network is executed with no integrity check: whoever controls the server or the connection controls this process. Pin the content by digest or verify a signature before running it")
}

# (3) a downloaded file is executed
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "urlretrieve(")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:subprocess\.(?:run|call|Popen|check_call|check_output)|os\.(?:system|exec\w*|spawn\w*|startfile))\s*\(`, line)
	not helpers.is_comment_line(line)
	some v in helpers.tainted_names(lines, i, 12, `urlretrieve\(`)
	regex.match(concat("", [`\b`, v, `\b`]), _code(_call_text(lines, i)))
	not _guarded(lines, i, _hash_re)
	finding := _finding(path, i, line, "A file downloaded with urlretrieve() is executed with no checksum or signature check. Verify its SHA-256 against a pinned value (or a signature) before running it")
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
