# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_618

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-618",
	"name": "ActiveX control marked safe for scripting, or unsafe control instantiated by a page",
	"description": "Reports an ActiveX control that declares itself callable by any web page, and pages that instantiate a control whose methods run commands or touch the file system. In C/C++: an ATL IObjectSafetyImpl<> base listing INTERFACESAFE_FOR_UNTRUSTED_CALLER or INTERFACESAFE_FOR_UNTRUSTED_DATA, a GetInterfaceSafetyOptions out-parameter (or an m_ member holding the current safety) set to those flags, IMPLEMENTED_CATEGORY(CATID_SafeForScripting / CATID_SafeForInitializing) and a component-category registration of those CATIDs; in .rgs/.reg registry scripts, the safe-for-scripting {7DD95801-...} and safe-for-initialising {7DD95802-...} category GUIDs. In HTML and JavaScript: an <object classid> of WScript.Shell, Shell.Application, Scripting.FileSystemObject or ADODB.Stream, and new ActiveXObject()/CreateObject() (in script blocks, .hta files and inline on* event-handler attributes) of WScript.Shell, WScript.Network, Shell.Application, Scripting.FileSystemObject, ADODB.Stream, Schedule.Service or WbemScripting.SWbemLocator. Every method of a control marked safe is reachable from untrusted script, so each finding needs review of what the exposed methods do. Not reported: .reg deletions ([-HKEY...]) and .rgs Delete entries that remove the category, the flag and GUID definitions themselves (#define, DEFINE_GUID, extern declarations), a SetInterfaceSafetyOptions mask test, ActiveX objects with no command or file capability (Msxml2.XMLHTTP, Microsoft.XMLDOM, media players), <object> embeds of media, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-618/",
	"languages": ["c", "cpp", "html", "node"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [618],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["exposed-unsafe-activex", "activex", "cwe-618"],
}

_native_ext := {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"}

_reg_ext := {".rgs", ".reg"}

_page_ext := {".html", ".htm", ".hta", ".js", ".asp", ".aspx"}

_has_ext(path, exts) if {
	some ext in exts
	endswith(lower(path), ext)
}

# `*pdwEnabledOptions = ...` starts with `*` but is a statement, not a
# block-comment continuation.
_c_comment(line) if {
	helpers.is_comment_line(line)
	not regex.match(`^\s*\*\s*\w+\s*\|?=[^=]`, line)
}

_strip_strings(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_message_native := "ActiveX control is marked safe for scripting/initialisation: any web page can call every method it exposes. Remove the safe-for-scripting claim, or restrict the control to approved sites (SiteLock) and make sure no method runs commands, reads or writes files, or trusts its arguments"

_message_page := "Page instantiates an ActiveX object that can run commands or touch the file system; any script able to reach it can do the same. Remove the ActiveX dependency"

_unsafe_clsid := `(?i)classid\s*=\s*["']?clsid:\s*\{?(72C24DD5-D70A-438B-8A42-98424B88AFB8|F935DC22-1CF0-11D0-ADB9-00C04FD58A0B|13709620-C279-11CE-A49E-444553540000|0D43FE01-F093-11CF-8940-00A0C9054228|00000566-0000-0010-8000-00AA006D2EA4)`

_unsafe_progid := `(?i)(new\s+ActiveXObject|\bCreateObject)\s*\(\s*["'](WScript\.Shell|WScript\.Network|Shell\.Application|Scripting\.FileSystemObject|ADODB\.Stream|Schedule\.Service|WbemScripting\.SWbemLocator)["']`

# ── C / C++ ────────────────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _native_ext)
	regex.match(`INTERFACESAFE_FOR_UNTRUSTED|CATID_SafeFor`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`INTERFACESAFE_FOR_UNTRUSTED|CATID_SafeFor|IObjectSafetyImpl`, line)
	not _c_comment(line)
	_native_claim(lines, i, _strip_strings(line))
	finding := {
		"rule_id": metadata.id,
		"message": _message_native,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# IObjectSafetyImpl<CX, INTERFACESAFE_FOR_UNTRUSTED_...> (template args may wrap)
_native_claim(lines, i, code) if {
	contains(code, "IObjectSafetyImpl")
	regex.match(`\bIObjectSafetyImpl\s*<`, code)
	win := concat(" ", array.slice(lines, i, min([count(lines), i + 3])))
	regex.match(`\bIObjectSafetyImpl\s*<[^>]*INTERFACESAFE_FOR_UNTRUSTED_(CALLER|DATA)`, win)
}

# *pdwEnabledOptions = INTERFACESAFE_FOR_UNTRUSTED_CALLER | ...
_native_claim(_, _, code) if {
	regex.match(`(^|[^\w])(\*\s*\w+|\w+\s*->\s*\w+|\bm_\w+)\s*\|?=\s*[^=;&]*\bINTERFACESAFE_FOR_UNTRUSTED_(CALLER|DATA)\b[^&]*$`, code)
}

# IMPLEMENTED_CATEGORY(CATID_SafeForScripting)
_native_claim(_, _, code) if {
	regex.match(`\bIMPLEMENTED_CATEGORY\s*\(\s*CATID_SafeFor(Scripting|Initializing)\b`, code)
}

# rgcatid[0] = CATID_SafeForScripting; RegisterClassImplCategories(..., &CATID_SafeForScripting)
_native_claim(_, _, code) if {
	not regex.match(`\b(DEFINE_GUID|EXTERN_C|extern|const\s+CATID|#define)\b`, code)
	regex.match(`(=\s*CATID_SafeFor(Scripting|Initializing)\b|(RegisterClassImplCategories|RegisterCLSIDInCategory|CreateComponentCategory)\s*\([^;]*CATID_SafeFor(Scripting|Initializing)\b)`, code)
}

# ── registry scripts ─────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _reg_ext)
	regex.match(`(?i)7DD9580[12]-9882-11CF-9FA9-00AA006C42C4`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)7DD9580[12]-9882-11CF-9FA9-00AA006C42C4`, line)
	not startswith(trim_space(line), ";")
	# `[-HKEY...]` in a .reg file and `Delete` in an .rgs script remove the category
	not startswith(trim_space(line), "[-")
	not regex.match(`(?i)^\s*Delete\b`, line)
	finding := {
		"rule_id": metadata.id,
		"message": _message_native,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── HTML / JavaScript ────────────────────────────────────────────────────
findings contains finding if {
	some path, content in input.file_contents
	_has_ext(path, _page_ext)
	regex.match(`(?i)classid|ActiveXObject|CreateObject`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)classid|ActiveXObject|CreateObject`, line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*<!--`, line)
	_page_unsafe(_unwrap_handler(line))
	finding := {
		"rule_id": metadata.id,
		"message": _message_page,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_page_unsafe(line) if regex.match(_unsafe_clsid, line)

_page_unsafe(line) if {
	regex.match(_unsafe_progid, line)
	# the call itself, not a mention inside a string literal
	not regex.match("[\"'`][^\"'`]*(ActiveXObject|CreateObject)\\s*\\(\\\\?[\"']", line)
}

# An inline event handler or a javascript: URL is script, not a string literal.
_unwrap_handler(line) := regex.replace(line, `(?i)(\bon[a-z]+\s*=\s*["']|["']javascript:)`, " ")
