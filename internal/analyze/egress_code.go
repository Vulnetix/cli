package analyze

// Egress from source code — only where the code actually talks to something.
//
// A regex over source cannot tell `"api.acme.io"` from `"business.metrics.direct"`:
// .io and .direct are both real TLDs, and a dotted string is a dotted string. What
// separates them is not the string, it is what the program DOES with it. So the
// code pass asks the parser instead, in three descending tiers of evidence:
//
//   call-site       the literal sits in the arguments of a call that opens a
//                   socket — http.Get, requests.post, net.Dial, curl, fetch.
//                   Nothing else needs to be true; this is a destination.
//   network-import  the file imports something that can reach the network, and
//                   the literal is a string containing only a host. The call may
//                   be three functions away — common, and worth a lower tier.
//   mention         neither. A host-shaped literal WITH a port, or a URL with a
//                   scheme. Inventory, not evidence.
//
// The queries capture the WHOLE call node rather than picking apart each grammar's
// argument fields, for two reasons: the capture map in reachability.Engine keeps
// one value per capture name (so N string arguments would collapse to the last),
// and every grammar spells its argument list differently while all of them spell
// "the call" the same way. Callee and arguments are split out of the node's text
// here, once, for every language.

import (
	"bytes"
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/vulnetix/cli/v3/internal/reachability"
	"github.com/vulnetix/cli/v3/internal/treesitter"
)

// Evidence tiers, strongest first. Recorded on the node rather than used to drop
// a host: "we saw this in a config file" and "the code calls it" are different
// facts, and a reader deciding what to chase needs both.
const (
	egressEvidenceCallSite      = "call-site"
	egressEvidenceNetworkImport = "network-import"
	egressEvidenceConfig        = "config"
	egressEvidenceManifest      = "manifest"
	egressEvidenceMention       = "mention"
)

var egressEvidenceRank = map[string]int{
	egressEvidenceCallSite:      0,
	egressEvidenceNetworkImport: 1,
	egressEvidenceConfig:        2,
	egressEvidenceManifest:      3,
	egressEvidenceMention:       4,
}

// bestEvidence is the strongest tier a host was seen at.
func bestEvidence(set map[string]bool) string {
	best := ""
	for e := range set {
		if best == "" || egressEvidenceRank[e] < egressEvidenceRank[best] {
			best = e
		}
	}

	return best
}

// egressCallQueries capture call sites. One capture per pattern, deliberately:
// the node's own text carries everything the callee test needs.
var egressCallQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo:         `(call_expression) @call`,
	treesitter.LangPython:     `(call) @call`,
	treesitter.LangJavaScript: `(call_expression) @call (new_expression) @call`,
	treesitter.LangTypeScript: `(call_expression) @call (new_expression) @call`,
	treesitter.LangTSX:        `(call_expression) @call (new_expression) @call`,
	treesitter.LangJava:       `(method_invocation) @call (object_creation_expression) @call`,
	treesitter.LangRust:       `(call_expression) @call (macro_invocation) @call`,
	treesitter.LangCSharp:     `(invocation_expression) @call (object_creation_expression) @call`,
	treesitter.LangPHP:        `(function_call_expression) @call (member_call_expression) @call`,
	treesitter.LangRuby:       `(call) @call`,
	treesitter.LangBash:       `(command) @call`,
}

// egressImportQueries capture what a file pulls in. Whole-node again — matching
// is a substring test against the module table, not a structural one.
var egressImportQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo:         `(import_spec) @import`,
	treesitter.LangPython:     `(import_statement) @import (import_from_statement) @import`,
	treesitter.LangJavaScript: `(import_statement) @import`,
	treesitter.LangTypeScript: `(import_statement) @import`,
	treesitter.LangTSX:        `(import_statement) @import`,
	treesitter.LangJava:       `(import_declaration) @import`,
	treesitter.LangRust:       `(use_declaration) @import`,
	treesitter.LangCSharp:     `(using_directive) @import`,
	treesitter.LangPHP:        `(namespace_use_declaration) @import`,
	treesitter.LangRuby:       `(call) @import`,
}

// networkCallees are the callee spellings that reach the network, per language.
//
// Entries are matched against the callee text lowercased. A leading dot means
// "any receiver, this method name" and is only used where the name alone is
// unambiguous — `.getasync` is HttpClient, `.get` is anything at all.
var networkCallees = map[treesitter.LanguageID][]string{
	treesitter.LangGo: {
		"http.get", "http.post", "http.head", "http.postform", "http.newrequest",
		"http.newrequestwithcontext", "http.readrequest", "http.redirecthandler",
		"net.dial", "net.dialtimeout", "net.dialtcp", "net.dialudp", "net.lookuphost",
		"net.lookupip", "net.resolvetcpaddr", "tls.dial", "tls.dialwithdialer",
		"grpc.dial", "grpc.newclient", "grpc.dialcontext",
		"smtp.dial", "smtp.sendmail", "smtp.plainauth",
		"url.parse", "url.parserequesturi",
		"amqp.dial", "redis.newclient", "mongo.connect", "sql.open", "pgx.connect",
		"pgxpool.new", "elastic.newclient", "s3.new", "kafka.dial",
		".setbasepath", ".sethost",
	},
	treesitter.LangPython: {
		"requests.get", "requests.post", "requests.put", "requests.patch",
		"requests.delete", "requests.head", "requests.request", "requests.session",
		"httpx.get", "httpx.post", "httpx.client", "httpx.asyncclient",
		"urlopen", "urllib.request.urlopen", "urllib.parse.urlparse",
		"aiohttp.clientsession", "aiohttp.request",
		"socket.create_connection", "socket.gethostbyname", ".connect",
		"smtplib.smtp", "smtplib.smtp_ssl", "ftplib.ftp",
		"psycopg2.connect", "pymongo.mongoclient", "redis.redis", "redis.from_url",
		"boto3.client", "boto3.resource", "kafkaproducer", "kafkaconsumer",
	},
	treesitter.LangJavaScript: {
		"fetch", "axios", "axios.get", "axios.post", "axios.put", "axios.patch",
		"axios.delete", "axios.request", "axios.create",
		"got", "got.get", "got.post", "superagent.get", "superagent.post",
		"http.request", "http.get", "https.request", "https.get",
		"net.connect", "net.createconnection", "tls.connect",
		"websocket", "eventsource", "io", "io.connect",
		"mongoclient", "createclient", "createconnection", "createpool",
		"new url", "url", "request",
	},
	treesitter.LangJava: {
		"httpclient.send", "httpclient.sendasync", "httprequest.newbuilder",
		".uri", ".url", "url", "uri.create", "socket", "sslsocket",
		"resttemplate.getforobject", "resttemplate.postforobject",
		"webclient.create", "okhttpclient", "request.builder",
	},
	treesitter.LangRust: {
		"reqwest::get", "reqwest::client::new", "client.get", "client.post",
		"tcpstream::connect", "udpsocket::bind", "ureq::get", "ureq::post",
		"hyper::client", "url::parse",
	},
	treesitter.LangCSharp: {
		".getasync", ".postasync", ".putasync", ".deleteasync", ".getstringasync",
		".downloadstring", ".downloadfile", ".openread",
		"httpclient", "webclient", "httprequestmessage", "tcpclient", "uri",
		"webrequest.create", "smtpclient",
	},
	treesitter.LangPHP: {
		"file_get_contents", "fopen", "fsockopen", "curl_init", "curl_setopt",
		"stream_context_create", "get_headers", "dns_get_record", "gethostbyname",
		"->request", "->get", "->post",
	},
	treesitter.LangRuby: {
		"net::http.get", "net::http.post", "net::http.start", "uri.parse",
		"restclient.get", "restclient.post", "httparty.get", "httparty.post",
		"tcpsocket.new", "open-uri", "faraday.new",
	},
	treesitter.LangBash: {
		"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
		"rsync", "git", "dig", "host", "nslookup", "ping", "traceroute",
		"aws", "gcloud", "az", "kubectl", "helm", "docker", "podman", "psql",
		"mysql", "mongo", "redis-cli", "openssl", "apt-get", "apk", "pip",
		"pip3", "npm", "yarn", "go", "cargo", "gem", "composer",
	},
}

// egressAssignQueries capture `name = "literal"`, which is what makes the
// call-site tier useful in practice.
//
// Almost nothing writes `http.Get("https://api.acme.io/v1")`. Real code writes
// `url := "https://api.acme.io/v1"` three lines earlier, or `URL="$1"` at the top
// of a shell script, and passes the variable. Without this hop the strongest tier
// finds nothing at all — measured on this repository: five network calls in
// install.sh, zero inline literals among them.
//
// One hop, same file, no scope analysis. A variable rebound between the
// assignment and the call would be read wrongly, which is the price of not
// building a dataflow engine; the tier below it catches the same host anyway.
var egressAssignQueries = map[treesitter.LanguageID]string{
	treesitter.LangGo: `
		(short_var_declaration left: (expression_list (identifier) @var) right: (expression_list (interpreted_string_literal) @val))
		(const_spec name: (identifier) @var value: (expression_list (interpreted_string_literal) @val))
		(var_spec name: (identifier) @var value: (expression_list (interpreted_string_literal) @val))
	`,
	treesitter.LangBash: `(variable_assignment name: (variable_name) @var value: (_) @val)`,
	treesitter.LangPython: `
		(assignment left: (identifier) @var right: (string) @val)
	`,
	treesitter.LangJavaScript: `
		(variable_declarator name: (identifier) @var value: (string) @val)
		(variable_declarator name: (identifier) @var value: (template_string) @val)
	`,
	treesitter.LangTypeScript: `
		(variable_declarator name: (identifier) @var value: (string) @val)
		(variable_declarator name: (identifier) @var value: (template_string) @val)
	`,
	treesitter.LangTSX: `
		(variable_declarator name: (identifier) @var value: (string) @val)
		(variable_declarator name: (identifier) @var value: (template_string) @val)
	`,
	treesitter.LangJava: `
		(variable_declarator name: (identifier) @var value: (string_literal) @val)
	`,
	treesitter.LangRust: `
		(let_declaration pattern: (identifier) @var value: (string_literal) @val)
	`,
	treesitter.LangCSharp: `
		(variable_declarator (identifier) @var (equals_value_clause (string_literal) @val))
	`,
	treesitter.LangRuby: `
		(assignment left: (identifier) @var right: (string) @val)
	`,
	treesitter.LangPHP: `
		(assignment_expression left: (variable_name) @var right: (string) @val)
	`,
}

// An identifier as it appears in an argument list, in any of the spellings the
// languages use: `url`, `$url`, `${url}`, `self.base_url`, `this.baseUrl`.
var egressIdentifierRef = regexp.MustCompile(`\$\{?([A-Za-z_][\w]*)\}?|\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\b`)

// networkModules gate the second tier: a file that imports none of these is not
// making a network call, whatever its string literals look like.
var networkModules = map[treesitter.LanguageID][]string{
	treesitter.LangGo: {
		"net/http", "net/url", "net/smtp", "net", "crypto/tls", "google.golang.org/grpc",
		"github.com/go-redis", "go.mongodb.org", "database/sql", "github.com/jackc/pgx",
		"github.com/aws/aws-sdk-go", "github.com/streadway/amqp", "nhooyr.io/websocket",
		"github.com/gorilla/websocket",
	},
	treesitter.LangPython: {
		"requests", "httpx", "urllib", "aiohttp", "socket", "http.client", "smtplib",
		"ftplib", "psycopg2", "pymongo", "redis", "boto3", "kafka", "websocket",
		"paramiko",
	},
	treesitter.LangJavaScript: {
		"axios", "node-fetch", "undici", "got", "superagent", "http", "https", "net",
		"tls", "ws", "socket.io-client", "mongodb", "pg", "mysql", "redis", "ioredis",
		"aws-sdk", "@aws-sdk", "nodemailer",
	},
	treesitter.LangJava: {
		"java.net", "java.net.http", "javax.net", "okhttp3", "org.apache.http",
		"org.springframework.web", "retrofit2", "javax.mail",
	},
	treesitter.LangRust: {
		"reqwest", "hyper", "ureq", "std::net", "tokio::net", "url", "surf",
	},
	treesitter.LangCSharp: {
		"system.net", "system.net.http", "system.net.sockets", "system.net.mail",
		"restsharp", "flurl",
	},
	treesitter.LangPHP:  {"guzzlehttp", "symfony\\component\\httpclient", "curl"},
	treesitter.LangRuby: {"net/http", "open-uri", "httparty", "rest-client", "faraday", "socket"},
}

// egressCombinedQueries is the three queries as one, per language.
//
// reachability.Engine parses on every Run, so asking it three questions about a
// file costs three parses — measured at 11.7s over this repository against 2.0s
// for the symbol pass. One query with three patterns costs one parse and returns
// every match; which pattern produced a match is read from its capture names.
var egressCombinedQueries = map[treesitter.LanguageID]string{}

func init() {
	// TypeScript and TSX are JavaScript for these purposes, and keeping three
	// copies of the same table in sync by hand is how they stop being the same.
	networkCallees[treesitter.LangTypeScript] = networkCallees[treesitter.LangJavaScript]
	networkCallees[treesitter.LangTSX] = networkCallees[treesitter.LangJavaScript]
	networkModules[treesitter.LangTypeScript] = networkModules[treesitter.LangJavaScript]
	networkModules[treesitter.LangTSX] = networkModules[treesitter.LangJavaScript]

	for lang, call := range egressCallQueries {
		egressCombinedQueries[lang] = strings.Join([]string{
			call, egressImportQueries[lang], egressAssignQueries[lang],
		}, "\n")
	}
}

// egressNetworkMarkers are the byte sequences that have to be present before a
// file is worth parsing. Deliberately broad — every network module, verb and
// scheme spelling in the tables above reduces to one of these — because a marker
// that is missing costs a whole tier of evidence, while a marker that is too
// generous costs one parse.
var egressNetworkMarkers = [][]byte{
	[]byte("://"), []byte("http"), []byte("socket"), []byte("dial"), []byte("curl"),
	[]byte("wget"), []byte("grpc"), []byte("smtp"), []byte("rsync"), []byte("axios"),
	[]byte("fetch("), []byte("requests."), []byte("net/"), []byte("net."),
	[]byte("webhook"), []byte("urlopen"), []byte("okhttp"), []byte("reqwest"),
	[]byte("scp "), []byte("ssh "),
}

func mightReachNetwork(src []byte) bool {
	low := bytes.ToLower(src)

	return slices.ContainsFunc(egressNetworkMarkers, func(marker []byte) bool {
		return bytes.Contains(low, marker)
	})
}

// splitCall divides a call node's text into the callee and everything inside its
// outermost parentheses. A shell command has no parentheses, so the whole text
// after the first word is its arguments.
func splitCall(text string) (callee, args string) {
	if head, rest, ok := strings.Cut(text, "("); ok {
		callee = strings.TrimSpace(head)
		args = rest
		if j := strings.LastIndex(args, ")"); j >= 0 {
			args = args[:j]
		}

		return callee, args
	}

	// Shell: `curl -sSL https://host/path`.
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return "", ""
	}

	return fields[0], strings.Join(fields[1:], " ")
}

// isNetworkCallee tests a callee against the language's table. Matching is on
// the tail of the expression so a receiver chain (`s.client.Get`) still matches
// the entry that names it (`.get` is deliberately absent from the tables where
// it would be meaningless).
func isNetworkCallee(lang treesitter.LanguageID, callee string) bool {
	c := strings.ToLower(strings.TrimSpace(callee))
	if c == "" {
		return false
	}

	// `new WebSocket(...)`, `new URL(...)` arrive with the keyword attached.
	c = strings.TrimPrefix(c, "new ")

	// A shell command may be a path: /usr/bin/curl.
	if lang == treesitter.LangBash {
		if i := strings.LastIndex(c, "/"); i >= 0 {
			c = c[i+1:]
		}
	}

	for _, want := range networkCallees[lang] {
		if c == want {
			return true
		}
		if strings.HasPrefix(want, ".") && strings.HasSuffix(c, want) {
			return true
		}
		// `http.Get` should match `nethttp.Get` never, but `client.http.Get` yes.
		if !strings.HasPrefix(want, ".") && strings.HasSuffix(c, "."+want) {
			return true
		}
	}

	return false
}

func importsNetworkModule(lang treesitter.LanguageID, imports []string) bool {
	mods := networkModules[lang]
	for _, imp := range imports {
		low := strings.ToLower(imp)
		for _, m := range mods {
			if strings.Contains(low, m) {
				return true
			}
		}
	}

	return false
}

// scanEgressCode is the code pass for one file. It records through the same sink
// as everything else so a host found here and in a workflow is one destination.
func scanEgressCode(
	ctx context.Context, engine *reachability.Engine, lang treesitter.LanguageID,
	src []byte, path string, record egressRecorder,
) {
	// PARSE ONLY WHAT COULD POSSIBLY MATTER. Parsing every source file cost 31s
	// over this repository — more than every other collector put together —
	// while the overwhelming majority of files contain nothing network-shaped at
	// all. A file with no scheme, no network module and no network verb in its
	// bytes cannot produce a call site or an import, so it goes straight to the
	// cheap text pass. Measured: 11,603 files scanned, a few hundred parsed.
	if !mightReachNetwork(src) {
		scanEgressText(string(src), egressSourceCode, path, true, egressEvidenceMention, record)

		return
	}

	query, ok := egressCombinedQueries[lang]
	if !ok {
		// An unsupported grammar falls back to the weakest tier rather than
		// reporting nothing: a host:port literal is still a host:port literal.
		scanEgressText(string(src), egressSourceCode, path, true, egressEvidenceMention, record)

		return
	}

	matches, err := engine.Run(ctx, lang, src, query)
	if err != nil {
		scanEgressText(string(src), egressSourceCode, path, true, egressEvidenceMention, record)

		return
	}

	// First pass: what the file imports, and what each name was assigned. Both
	// have to be known before any call is read, which is why this is two passes
	// over one match list rather than two passes over the file.
	imports := []string{}
	assigned := map[string][]string{}
	for _, m := range matches {
		if text, isImport := m.Captures["import"]; isImport {
			imports = append(imports, text)
		}

		name := strings.TrimPrefix(strings.TrimSpace(m.Captures["var"]), "$")
		value := m.Captures["val"]
		if name != "" && value != "" && !slices.Contains(assigned[name], value) {
			// EVERY literal a name was given, not the last one. A name assigned
			// two hosts in one file reaches both, and choosing one of them would
			// be a guess presented as a fact.
			assigned[name] = append(assigned[name], value)
		}
	}
	networked := importsNetworkModule(lang, imports)

	calls := 0
	for _, m := range matches {
		text := m.Captures["call"]
		if text == "" {
			continue
		}
		callee, args := splitCall(text)
		if !isNetworkCallee(lang, callee) {
			continue
		}
		calls++

		// Inside the arguments of a network call, a bare host needs no port and
		// no scheme to be believed — that is the entire point of asking the
		// parser. Nested calls appear as their own matches, so nothing is lost
		// by reading only this call's own argument text.
		scanEgressArguments(args, path, m.StartLine, callee, assigned, record)
	}

	// Tiers 2 and 3 over the file's own literals. `quotedOnly` keeps field
	// access (`resp.data`, `p.name`) out; the evidence tier is what changes.
	//
	// A file that CALLS the network counts the same as one that imports it: the
	// call is the stronger signal of the two, and a file can reach the network
	// through a helper it was handed rather than through its own import.
	evidence := egressEvidenceMention
	if networked || calls > 0 {
		evidence = egressEvidenceNetworkImport
	}
	scanEgressText(string(src), egressSourceCode, path, true, evidence, record)
}

// scanEgressArguments pulls hosts out of one call's argument text, and out of
// the literals its variables were assigned.
func scanEgressArguments(
	args, path string, line int, callee string, assigned map[string][]string,
	record egressRecorder,
) {
	seen := map[string]bool{}

	emit := func(host, scheme string) {
		if seen[host] || !isEgressHost(host) {
			return
		}
		seen[host] = true
		record(egressSighting{
			Host: host, Scheme: scheme, Source: egressSourceCode, Path: path,
			Line: line, Evidence: egressEvidenceCallSite, Callee: callee,
		})
	}

	// The variables this call was handed. `curl -fsSL "$url"` says nothing on its
	// own; `url="https://cli.vulnetix.com/install.sh"` two lines up says it all.
	if len(assigned) > 0 {
		for _, ref := range egressIdentifierRef.FindAllStringSubmatch(args, -1) {
			name := ref[1]
			if name == "" {
				name = ref[2]
			}
			values, ok := assigned[name]
			if !ok {
				// `this.baseUrl` / `self.base_url`: try the tail too.
				if _, tail, cut := strings.Cut(name, "."); cut {
					values, ok = assigned[tail]
				}
				if !ok {
					continue
				}
			}

			for _, value := range values {
				for _, u := range egressURLPattern.FindAllStringSubmatch(value, -1) {
					emit(normaliseHost(u[2]), strings.ToLower(u[1]))
				}
				if host, _, isHost := literalHost(strings.Trim(value, "\"'`")); isHost &&
					!hasFileExtensionTLD(host) {
					emit(host, "")
				}
			}
		}
	}

	for _, m := range egressURLPattern.FindAllStringSubmatch(args, -1) {
		host := normaliseHost(m[2])
		if seen[host] || !isEgressHost(host) {
			continue
		}
		seen[host] = true
		record(egressSighting{
			Host: host, Scheme: strings.ToLower(m[1]), Source: egressSourceCode,
			Path: path, Line: line, Evidence: egressEvidenceCallSite, Callee: callee,
		})
	}

	// Bare hosts, but only from string literals: an argument list contains
	// identifiers too, and `cfg.timeout.seconds` is not a destination.
	for _, literal := range quotedLiteral.FindAllString(egressURLPattern.ReplaceAllString(args, " "), -1) {
		host, _, ok := literalHost(literal)
		if !ok || seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) {
			continue
		}
		seen[host] = true
		record(egressSighting{
			Host: host, Source: egressSourceCode, Path: path, Line: line,
			Evidence: egressEvidenceCallSite, Callee: callee,
		})
	}

	// Shell has no quotes to rely on: `curl -sSL https://x` and `nc mail.acme.io 25`
	// are both bare. The callee gate is what makes this safe.
	if !strings.Contains(args, "\"") && !strings.Contains(args, "'") {
		for _, m := range egressHostPattern.FindAllStringSubmatch(args, -1) {
			host := normaliseHost(m[1])
			if seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) {
				continue
			}
			seen[host] = true
			record(egressSighting{
				Host: host, Source: egressSourceCode, Path: path, Line: line,
				Evidence: egressEvidenceCallSite, Callee: callee,
			})
		}
	}
}
