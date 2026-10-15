# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_781

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-781",
	"name": "Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code",
	"description": "A Windows kernel driver reads the raw user-mode buffer pointer of a METHOD_NEITHER IOCTL without validating it, so a user process can pass a kernel address and make the driver read or write kernel memory. Reported, in C and C++ driver sources: a read of IO_STACK_LOCATION Parameters.DeviceIoControl.Type3InputBuffer or of Irp->UserBuffer, or a KMDF WdfRequestRetrieveUnsafeUserInputBuffer/OutputBuffer call, when no ProbeForRead, ProbeForWrite, MmProbeAndLockPages or WdfRequestProbeAndLockUserBufferForRead/ForWrite call appears in the 30 code lines above or 40 below it. Not reported: METHOD_BUFFERED and direct-I/O buffers (AssociatedIrp.SystemBuffer, MdlAddress), assignments to UserBuffer, user-mode code that only calls DeviceIoControl, comments and string literals. Whether the probe covers the same pointer and length, and runs inside __try, is not checked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-781/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [781],
	"capec": ["CAPEC-97"],
	"attack_technique": ["T1557"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["windows-driver", "ioctl", "method-neither", "cwe-781"],
}

_c_ext := {"c", "cc", "cpp", "cxx", "h", "hpp", "hh"}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# A read of the user pointer (not an assignment to the field).
_reads_user_ptr(c) if regex.match(`\bDeviceIoControl\s*\.\s*Type3InputBuffer\b`, c)

_reads_user_ptr(c) if {
	regex.match(`(?:->|\.)\s*UserBuffer\b`, c)
	not regex.match(`(?:->|\.)\s*UserBuffer\s*=[^=]`, c)
}

# KMDF: the unsafe-buffer accessors return the raw METHOD_NEITHER pointer.
_reads_user_ptr(c) if regex.match(`\bWdfRequestRetrieveUnsafeUser(?:Input|Output)Buffer\s*\(`, c)

_mentions_user_ptr(content) if contains(content, "WdfRequestRetrieveUnsafeUser")

_mentions_user_ptr(content) if contains(content, "Type3InputBuffer")

_mentions_user_ptr(content) if contains(content, "UserBuffer")

_probed(lines, i) if {
	window := helpers.code_window(lines, i, 30, 40)
	regex.match(`\b(?:ProbeForRead|ProbeForWrite|MmProbeAndLockPages|WdfRequestProbeAndLockUserBufferFor(?:Read|Write))\s*\(`, window)
}

findings contains f if {
	some path, content in input.file_contents
	_mentions_user_ptr(content)
	regex.replace(path, `^.*\.`, "") in _c_ext
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Type3InputBuffer|UserBuffer|WdfRequestRetrieveUnsafeUser`, line)
	not helpers.is_comment_line(line)
	_reads_user_ptr(_code(line))
	not _probed(lines, i)
	f := {
		"rule_id": metadata.id,
		"message": "METHOD_NEITHER user buffer pointer used without ProbeForRead/ProbeForWrite: a caller can pass a kernel address. Probe it inside __try/__except, or use METHOD_BUFFERED",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
