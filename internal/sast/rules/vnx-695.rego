# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_695

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-695",
	"name": "Low-level functionality prohibited by the EJB specification used in an enterprise bean",
	"description": "An Enterprise JavaBean uses low-level functionality that the EJB specification forbids because the container owns it: the container manages threads, connections, files, synchronisation and the JVM lifecycle, and a bean that does this itself breaks pooling, transactions, security and clustering. Reported in a .java file that imports javax.ejb/jakarta.ejb (or uses a fully qualified @javax.ejb./@jakarta.ejb. annotation) and declares a bean (@Stateless, @Stateful, @Singleton, @MessageDriven, or implements SessionBean/EntityBean/MessageDrivenBean): creating threads or thread pools (new Thread(, Executors.new..., new ThreadPoolExecutor/ForkJoinPool/Timer), listening on a socket or joining multicast (new ServerSocket, new MulticastSocket, new DatagramSocket(port), ServerSocketChannel.open()), java.io file access (new FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile), native code (System.loadLibrary/System.load, a native method declaration), synchronized methods and blocks, System.exit/Runtime.halt, and replacing the standard streams, security manager or a class loader (System.setOut/setErr/setIn/setSecurityManager, new ...ClassLoader(, setContextClassLoader). Not reported: client sockets (new Socket(host, port), new DatagramSocket()), which the specification allows; the same code in classes that are not EJBs (Spring @Service, javax.inject.Singleton, plain classes), container-managed alternatives (ManagedExecutorService, @Asynchronous, @Resource connection factories), comments, string literals and lookalike identifiers. Helper classes called from a bean are not followed. Inline assembly in C, which the original rule reported, is not prohibited by any specification and is no longer reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-695/",
	"languages": ["java"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [695],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["low-level-functionality", "ejb", "j2ee", "cwe-695"],
}

_ejb_import := `(?m)^\s*import\s+(?:javax|jakarta)\.ejb\.|^\s*@(?:javax|jakarta)\.ejb\.`

_ejb_bean := `(?m)^\s*@(?:(?:javax|jakarta)\.ejb\.)?(?:Stateless|Stateful|Singleton|MessageDriven)\b|\bimplements\s+[^{]*\b(?:SessionBean|EntityBean|MessageDrivenBean)\b`

# javax.inject.Singleton / jakarta.inject.Singleton is a CDI scope, not an EJB.
_cdi_only(content) if {
	regex.match(`(?m)^\s*import\s+(?:javax|jakarta)\.inject\.Singleton\s*;`, content)
	not regex.match(`(?m)^\s*@(?:(?:javax|jakarta)\.ejb\.)?(?:Stateless|Stateful|MessageDriven)\b|^\s*@(?:javax|jakarta)\.ejb\.Singleton\b|\bimplements\s+[^{]*\b(?:SessionBean|EntityBean|MessageDrivenBean)\b`, content)
}

# The specification lets a bean be a socket client; it forbids listening,
# accepting and multicast. new DatagramSocket() with no argument is a client;
# with a port or address it binds.
_checks := [
	[`\bnew\s+Thread\s*\(|\bExecutors\s*\.\s*new\w+\s*\(|\bnew\s+(?:ThreadPoolExecutor|ScheduledThreadPoolExecutor|ForkJoinPool|Timer)\s*\(`, "creates its own thread"],
	[`\bnew\s+(?:ServerSocket|MulticastSocket)\s*\(|\bnew\s+DatagramSocket\s*\(\s*[^\s)]|\b(?:Asynchronous)?ServerSocketChannel\s*\.\s*open\s*\(`, "listens on a socket or joins a multicast group"],
	[`\bnew\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(`, "reads or writes a file through java.io"],
	[`\bSystem\s*\.\s*(?:loadLibrary|load)\s*\(|^\s*(?:(?:public|private|protected|static|final)\s+)*native\s+[\w<>\[\], ]+\s+\w+\s*\(`, "loads or declares native code"],
	[`\bsynchronized\s*\(|^\s*(?:(?:public|private|protected|static|final)\s+)*synchronized\s+[\w<>\[\], ]+\s+\w+\s*\(`, "uses a synchronization primitive"],
	[`\bSystem\s*\.\s*exit\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*halt\s*\(`, "stops the JVM"],
	[`\bSystem\s*\.\s*set(?:Out|Err|In|SecurityManager)\s*\(|\bnew\s+\w*ClassLoader\s*\(|\.\s*setContextClassLoader\s*\(`, "replaces the standard streams, the security manager or a class loader"],
]

_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "ejb")
	regex.match(_ejb_import, content)
	regex.match(_ejb_bean, content)
	not _cdi_only(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _code(line)
	some c in _checks
	regex.match(c[0], code)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("This enterprise bean %s, which the EJB specification reserves to the container; use the container's managed service instead", [c[1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
