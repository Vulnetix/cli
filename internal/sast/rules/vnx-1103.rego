# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1103

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1103",
	"name": "Use of Platform-Dependent Third Party Components",
	"description": "Java or Kotlin code imports or names a JDK-implementation-internal package that is not part of the Java SE platform and is not guaranteed to exist, or to behave the same, on another JVM, JDK vendor or release: sun.* (sun.misc.Unsafe, sun.misc.BASE64Encoder, sun.security.*, sun.nio.ch.*), jdk.internal.*, the com.sun.*.internal.* and com.sun.org.apache.* repackaged copies, and the unexported implementation packages com.sun.crypto.provider, com.sun.jndi, com.sun.imageio, com.sun.media.sound and com.sun.java.swing. Code built on them breaks on a JDK upgrade or a different runtime (BASE64Encoder was removed in Java 9; jdk.internal is closed by the module system). Reported: each import, static import and fully qualified use in code. Not reported: the supported, exported com.sun APIs (com.sun.net.httpserver, com.sun.management, com.sun.jna), the standard replacements (java.util.Base64, VarHandle), class names inside string literals (the reflective probe-and-fall-back pattern), third-party libraries that merely live under com.sun (com.sun.mail, com.sun.jersey, the com.sun.xml.bind and com.sun.xml.ws reference implementations), lookalike packages (sunrise, sunflower) and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1103/",
	"languages": ["java", "kotlin"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1103],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["portability", "jdk-internal", "java", "cwe-1103"],
}

_internal_re := `(?:^|[^\w.])(?:sun\.(?:misc|security|nio\.(?:ch|cs|fs)|reflect|net\.www|rmi|awt|font|java2d|util|io|jvmstat|management|tools|corba|swing)\.[A-Za-z_*]|jdk\.internal\.[A-Za-z_*]|com\.sun\.(?:[a-z_]\w*\.)*internal\.[A-Za-z_*]|com\.sun\.org\.apache\.[A-Za-z_*]|com\.sun\.(?:crypto\.provider|jndi|imageio|media\.sound|java\.swing)\.[A-Za-z_*])`

_gate_re := `(?:\bsun\.(?:misc|security|nio|reflect|net|rmi|awt|font|java2d|util|io|jvmstat|management|tools|corba|swing)\.|jdk\.internal\.|com\.sun\.)`

_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$|/\*.*?\*/`, "")

findings contains finding if {
	some path, content in input.file_contents
	regex.match(`\.(?:java|kt|kts)$`, path)
	regex.match(_gate_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate_re, line)
	not helpers.is_comment_line(line)
	regex.match(_internal_re, _code(line))
	finding := {
		"rule_id": metadata.id,
		"message": "JDK-internal package (sun.*, jdk.internal.*, com.sun.*.internal) is not part of the Java SE platform and differs or disappears across JDK vendors and releases; use the supported API (java.util.Base64, VarHandle, java.lang.foreign) instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
