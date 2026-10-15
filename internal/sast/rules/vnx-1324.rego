# SPDX-License-Identifier: Apache-2.0
# CWE-1324 (deprecated upstream): sensitive information accessible through a
# hardware debug port (JTAG/SWD) left enabled in production firmware.

package vulnetix.rules.vnx_1324

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1324",
	"name": "Hardware debug interface (JTAG/SWD) enabled in firmware outside a debug build",
	"description": "Firmware code that turns a hardware debug port on, or keeps it alive, outside a debug-only preprocessor block: STM32 DBGMCU->CR |= DBGMCU_CR_DBG_* and HAL_DBGMCU_EnableDBGSleepMode/StopMode/StandbyMode() (and the LL_DBGMCU_ and older HAL_EnableDBG* spellings), Cortex-M CoreDebug->DHCSR written with C_DEBUGEN set (0xA05F0001-style keys or |= CoreDebug_DHCSR_C_DEBUGEN_Msk), __HAL_AFIO_REMAP_SWJ_ENABLE(), AVR MCUCR &= ~(1 << JTD) (clearing the JTAG-disable bit), nRF APPROTECT set to HwDisabled/SwDisable, and assignments of 1/true to a JTAG/SWD enable flag. A production device that ships with its debug port open lets anyone with physical access read flash, keys and RAM. Not reported: the same code inside #ifdef DEBUG, #if defined(DEBUG...), #if DEBUG or #ifndef NDEBUG blocks; code that disables debug access (&= ~, Disable* calls, DHCSR written without C_DEBUGEN, JTD set); CoreDebug->DEMCR TRCENA used for the DWT cycle counter; macro definitions, prototypes, comments and strings. Option bytes, fuses and linker-level configuration are not examined.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1324/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1324],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["firmware", "jtag", "swd", "debug-interface", "embedded", "cwe-1324"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_kws := ["DBGMCU", "EnableDBG", "CoreDebug", "SWJ_", "JTD", "APPROTECT", "JTAG", "jtag", "Jtag", "SWD", "swd", "Swd"]

_has_kw(s) if {
	some kw in _kws
	contains(s, kw)
}

_enable_res := [
	`DBGMCU\s*->\s*CR\s*\|=\s*[^;]*DBGMCU_CR_DBG_`,
	`\b(?:HAL|LL)_(?:DBGMCU_)?EnableDBG(?:Sleep|Stop|Standby)Mode\s*\(\s*\)\s*;`,
	`CoreDebug\s*->\s*DHCSR\s*=\s*\(?\s*0[xX][aA]05[fF][0-9a-fA-F]{3}[13579bBdDfF]\b`,
	`CoreDebug\s*->\s*DHCSR\s*\|=\s*[^;]*C_DEBUGEN`,
	`\b__HAL_AFIO_REMAP_SWJ_(?:ENABLE|NOJTAG)\s*\(\s*\)`,
	`\bMCUCR\s*&=\s*~\s*\(?\s*(?:1\s*<<\s*JTD|_BV\s*\(\s*JTD\s*\)|\(\s*1\s*<<\s*JTD\s*\))`,
	`APPROTECT\s*(?:->\s*DISABLE\s*)?=\s*\(?\s*(?:UICR_APPROTECT_PALL_HwDisabled|APPROTECT_DISABLE_DISABLE_SwDisable|0x5[aA]\b)`,
	`\b(?i:jtag|swd)_?(?i:en|enable|enabled)\s*=\s*(?:1|true|TRUE)\s*;`,
]

_enables(code) if {
	some re in _enable_res
	regex.match(re, code)
}

_strip(l) := regex.replace(regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`), `/\*.*?\*/|//.*$`, "")

_debug_name := `(?:_?DEBUG|DEBUG_BUILD|DEBUG_MODE|ENABLE_DEBUG\w*|CONFIG_DEBUG\w*|USE_FULL_ASSERT|BRINGUP|BRING_UP)`

# A preprocessor line that opens a debug-only block.
_debug_open(l) if regex.match(concat("", [`^\s*#\s*ifdef\s+`, _debug_name, `\b`]), l)

_debug_open(l) if regex.match(concat("", [`^\s*#\s*(?:el)?if\s+\(?\s*`, _debug_name, `\b`]), l)

_debug_open(l) if {
	regex.match(concat("", [`^\s*#\s*(?:el)?if\b.*\bdefined\s*\(?\s*`, _debug_name, `\b`]), l)
	not regex.match(concat("", [`!\s*defined\s*\(?\s*`, _debug_name, `\b`]), l)
}

_debug_open(l) if regex.match(`^\s*#\s*ifndef\s+NDEBUG\b`, l)

_debug_open(l) if regex.match(`^\s*#\s*if\b.*!\s*defined\s*\(?\s*NDEBUG\b`, l)

_pp_open(l) if regex.match(`^\s*#\s*if`, l)

_pp_close(l) if regex.match(`^\s*#\s*endif\b`, l)

_pp_else(l) if regex.match(`^\s*#\s*el(?:se|if)\b`, l)

# depth of nested #if blocks opened in lines (a, b], relative to a
_depth(_, a, b) := 0 if a + 1 > b

_depth(lines, a, b) := d if {
	a + 1 <= b
	d := count([k | some k in numbers.range(a + 1, b); _pp_open(lines[k])]) - count([k | some k in numbers.range(a + 1, b); _pp_close(lines[k])])
}

# Line i sits in the "true" branch of a debug-only block opened at j.
_in_debug_block(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 200]), i - 1)
	_debug_open(lines[j])
	not _closed_between(lines, j, i)
	not _else_between(lines, j, i)
}

# some #endif in between brings the depth below the block j opened
_closed_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	_pp_close(lines[k])
	_depth(lines, j, k) < 0
}

_else_between(lines, j, i) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	_pp_else(lines[k])
	_depth(lines, j, k - 1) == 0
}

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	_has_kw(content)
	lines := split(content, "\n")
	some i, line in lines
	_has_kw(line)
	not helpers.is_comment_line(line)
	not regex.match(`^\s*#`, line)
	code := _strip(line)
	_enables(code)
	not _in_debug_block(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Hardware debug interface (JTAG/SWD/debug-in-low-power) is enabled outside a debug-only build block; production firmware that ships with an open debug port exposes flash, keys and RAM to anyone with physical access. Guard it with #ifdef DEBUG or remove it from release builds",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
