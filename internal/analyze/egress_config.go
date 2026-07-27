package analyze

// Egress from configuration — read the format, not the text.
//
// Configuration is where the interesting hosts are: the registry a build pulls
// from, the webhook a workflow posts to, the DNS record Terraform declares. It is
// also where a text scan does its worst work, because every one of these formats
// has an expression syntax whose identifiers are shaped exactly like hostnames:
//
//     ${{ steps.scan.outputs.total }}     GitHub Actions
//     (http.host eq "vulnetix.com")       Cloudflare rules in Terraform
//     ${var.region}, each.value           HCL
//
// `.total`, `.host` and `.value` are all real TLDs, so shape and delegation
// cannot separate them. Structure can: in YAML a host is a scalar VALUE, never a
// key; in HCL a host is a quoted literal, never a traversal; in an env file it is
// the right-hand side of `=`; in a Dockerfile it belongs to particular
// instructions. So each format is read as itself.
//
// The key a host was found under is recorded. `registry` and `endpoint` say
// something a line number does not.

import (
	"encoding/json"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// Templating spans, blanked before any scan. `${{ … }}` is Actions, `${…}`
	// is HCL/shell/compose, `{{ … }}` is Helm and Go templates. What is inside
	// them is a reference to a value, not a value.
	egressTemplateSpan = regexp.MustCompile(`\$\{\{[^}]*\}\}|\$\{[^}]*\}|\{\{[^}]*\}\}`)

	// `attribute = "value"` in HCL, TOML, .properties and .ini alike.
	egressAssignment = regexp.MustCompile(`(?m)^[\t ]*([A-Za-z_][\w.\-]*)[\t ]*[:=][\t ]*(.+)$`)
)

// Key names whose value is a destination by definition. Not a gate — a host is
// still a host under `notes` — but it is what makes the drawer readable.
var egressDestinationKeys = map[string]bool{
	"url": true, "uri": true, "host": true, "hostname": true, "endpoint": true,
	"server": true, "registry": true, "mirror": true, "proxy": true, "broker": true,
	"webhook": true, "dsn": true, "address": true, "origin": true, "upstream": true,
	"domain": true, "base_url": true, "baseurl": true, "api_url": true, "apiurl": true,
	"repository": true, "resolved": true, "tarball": true, "index_url": true,
}

// scanEgressConfig dispatches one configuration file to the reader that
// understands it.
func scanEgressConfig(body, source, path string, record egressRecorder) {
	base := strings.ToLower(path)
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	ext := fileExtension(base)

	switch {
	case ext == ".yaml" || ext == ".yml":
		scanEgressYAML(body, source, path, record)

	case ext == ".json":
		scanEgressJSON(body, source, path, record)

	case strings.HasPrefix(base, "dockerfile"), strings.HasPrefix(base, "containerfile"),
		strings.HasSuffix(base, ".dockerfile"):
		scanEgressDockerfile(body, source, path, record)

	case strings.HasPrefix(base, ".env"), strings.HasSuffix(base, ".env"):
		scanEgressAssignments(body, source, path, record)

	case ext == ".tf" || ext == ".tfvars" || ext == ".hcl" || ext == ".nix" ||
		ext == ".toml" || ext == ".ini" || ext == ".cfg" || ext == ".properties":
		scanEgressAssignments(body, source, path, record)
	}

	// Anything else — .conf, .xml, .gradle, lockfiles with no parser here — falls
	// back to a line scan, at the WEAKEST tier. Without a grammar there is no way
	// to tell a configured destination from prose: this repository publishes
	// generated documentation as XML, and those files discuss half the internet.
	// Blanking the template spans first is what keeps `${{ steps.scan.outputs.total }}`
	// out of it.
	if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".tf" ||
		ext == ".tfvars" || ext == ".hcl" || ext == ".nix" || ext == ".toml" ||
		ext == ".ini" || ext == ".cfg" || ext == ".properties" ||
		strings.HasPrefix(base, "dockerfile") || strings.HasPrefix(base, "containerfile") ||
		strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env") {
		return
	}

	// URLs only. In a format nothing here can parse, a bare dotted string has no
	// context at all — `http.host` in a paragraph about Cloudflare rules is
	// indistinguishable from a hostname — while a scheme says what the string is.
	scanEgressURLs(egressTemplateSpan.ReplaceAllString(body, " "), source, path,
		egressEvidenceMention, record)
}

// scanEgressURLs records only what carries a scheme.
func scanEgressURLs(body, source, path, evidence string, record egressRecorder) {
	lineNo := 0
	for line := range strings.SplitSeq(body, "\n") {
		lineNo++

		for _, u := range egressURLPattern.FindAllStringSubmatch(line, -1) {
			host := normaliseHost(u[2])
			if !isEgressHost(host) {
				continue
			}
			record(egressSighting{
				Host: host, Scheme: strings.ToLower(u[1]), Source: source,
				Path: path, Line: lineNo, Evidence: evidence,
			})
		}
	}
}

// scanEgressYAML walks the document tree. Only scalar VALUES are read, so a key
// named `api.example.com` — which happens, in ingress rules — is not mistaken for
// a destination this file configures, and comments never reach the scanner at all.
func scanEgressYAML(body, source, path string, record egressRecorder) {
	dec := yaml.NewDecoder(strings.NewReader(body))

	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break
		}
		walkYAMLNode(&doc, "", source, path, record)
	}
}

func walkYAMLNode(n *yaml.Node, keyPath, source, path string, record egressRecorder) {
	if n == nil {
		return
	}

	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkYAMLNode(c, keyPath, source, path, record)
		}

	case yaml.MappingNode:
		// Content alternates key, value, key, value.
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			next := key.Value
			if keyPath != "" {
				next = keyPath + "." + key.Value
			}
			walkYAMLNode(value, next, source, path, record)
		}

	case yaml.SequenceNode:
		for _, c := range n.Content {
			walkYAMLNode(c, keyPath, source, path, record)
		}

	case yaml.ScalarNode:
		recordEgressValue(n.Value, keyPath, source, path, n.Line, record)
	}
}

// scanEgressJSON reads values only, the same way, which is what makes a lockfile
// useful here: `resolved` and `tarball` are fetch URLs, and the keys around them
// are package names that are frequently host-shaped.
func scanEgressJSON(body, source, path string, record egressRecorder) {
	var doc any
	if json.Unmarshal([]byte(body), &doc) != nil {
		return
	}
	walkJSONValue(doc, "", source, path, record)
}

func walkJSONValue(v any, keyPath, source, path string, record egressRecorder) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			next := k
			if keyPath != "" {
				next = keyPath + "." + k
			}
			walkJSONValue(child, next, source, path, record)
		}
	case []any:
		for _, child := range t {
			walkJSONValue(child, keyPath, source, path, record)
		}
	case string:
		recordEgressValue(t, keyPath, source, path, 0, record)
	}
}

// scanEgressAssignments handles every `key = value` format: HCL, TOML, .env,
// .properties, .ini. The value side only — an HCL traversal (`http.host`,
// `each.value`, `var.region`) is bare, never quoted, so requiring a quoted
// literal or a URL removes that entire false-positive class without a denylist.
func scanEgressAssignments(body, source, path string, record egressRecorder) {
	lineNo := 0
	for line := range strings.SplitSeq(body, "\n") {
		lineNo++

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		m := egressAssignment.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := strings.ToLower(m[1]), egressTemplateSpan.ReplaceAllString(m[2], " ")

		// URLs are unambiguous wherever they appear on the value side.
		seen := map[string]bool{}
		for _, u := range egressURLPattern.FindAllStringSubmatch(value, -1) {
			host := normaliseHost(u[2])
			if seen[host] || !isEgressHost(host) {
				continue
			}
			seen[host] = true
			record(egressSighting{
				Host: host, Scheme: strings.ToLower(u[1]), Source: source, Path: path,
				Line: lineNo, Evidence: egressEvidenceConfig, KeyPath: key,
			})
		}

		rest := egressURLPattern.ReplaceAllString(value, " ")

		// A quoted literal that is nothing but a host. `expression = "(http.host
		// eq \"vulnetix.com\")"` is not one — it has spaces — and the quoted
		// `vulnetix.com` inside it is reached by the URL pass or not at all.
		for _, literal := range quotedLiteral.FindAllString(rest, -1) {
			host, _, ok := literalHost(literal)
			if !ok || seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) ||
				!isCommonNetworkTLD(host) {
				continue
			}
			seen[host] = true
			record(egressSighting{
				Host: host, Source: source, Path: path, Line: lineNo,
				Evidence: egressEvidenceConfig, KeyPath: key,
			})
		}

		// An unquoted value under a key that names a destination: `MAIL_HOST=smtp.acme.io`.
		if !strings.ContainsAny(rest, "\"'`") && egressDestinationKeys[strings.TrimPrefix(key, "_")] {
			for _, h := range egressHostPattern.FindAllStringSubmatch(rest, -1) {
				host := normaliseHost(h[1])
				if seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) ||
					!isCommonNetworkTLD(host) {
					continue
				}
				seen[host] = true
				record(egressSighting{
					Host: host, Source: source, Path: path, Line: lineNo,
					Evidence: egressEvidenceConfig, KeyPath: key,
				})
			}
		}
	}
}

// Dockerfile instructions that reach the network. `FROM` names a registry, `RUN`
// runs a shell (curl, apt, pip), `ADD` accepts a remote URL.
var egressDockerInstructions = map[string]bool{
	"from": true, "run": true, "add": true, "copy": true, "env": true, "arg": true,
}

func scanEgressDockerfile(body, source, path string, record egressRecorder) {
	lineNo := 0
	for line := range strings.SplitSeq(body, "\n") {
		lineNo++

		trimmed := strings.TrimSpace(egressTemplateSpan.ReplaceAllString(line, " "))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !egressDockerInstructions[strings.ToLower(fields[0])] {
			continue
		}

		instruction := strings.ToLower(fields[0])
		rest := strings.Join(fields[1:], " ")

		seen := map[string]bool{}
		for _, u := range egressURLPattern.FindAllStringSubmatch(rest, -1) {
			host := normaliseHost(u[2])
			if seen[host] || !isEgressHost(host) {
				continue
			}
			seen[host] = true
			record(egressSighting{
				Host: host, Scheme: strings.ToLower(u[1]), Source: source, Path: path,
				Line: lineNo, Evidence: egressEvidenceConfig, KeyPath: instruction,
			})
		}

		// `FROM ghcr.io/acme/base:1.2` — the registry is bare, and it is the whole
		// point of the instruction, so bare is read here and nowhere else.
		if instruction == "from" || instruction == "run" || instruction == "add" {
			for _, h := range egressHostPattern.FindAllStringSubmatch(
				egressURLPattern.ReplaceAllString(rest, " "), -1) {
				host := normaliseHost(h[1])
				if seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) ||
					!isCommonNetworkTLD(host) {
					continue
				}
				seen[host] = true
				record(egressSighting{
					Host: host, Source: source, Path: path, Line: lineNo,
					Evidence: egressEvidenceConfig, KeyPath: instruction,
				})
			}
		}
	}
}

// recordEgressValue is the shared tail for the tree-walking formats: one scalar,
// already known to be a value rather than a key.
func recordEgressValue(
	value, keyPath, source, path string, line int, record egressRecorder,
) {
	value = egressTemplateSpan.ReplaceAllString(value, " ")
	if strings.TrimSpace(value) == "" {
		return
	}

	key := keyPath
	if i := strings.LastIndex(key, "."); i >= 0 {
		key = key[i+1:]
	}
	key = strings.ToLower(key)

	seen := map[string]bool{}
	for _, u := range egressURLPattern.FindAllStringSubmatch(value, -1) {
		host := normaliseHost(u[2])
		if seen[host] || !isEgressHost(host) {
			continue
		}
		seen[host] = true
		record(egressSighting{
			Host: host, Scheme: strings.ToLower(u[1]), Source: source, Path: path,
			Line: line, Evidence: egressEvidenceConfig, KeyPath: keyPath,
		})
	}

	rest := strings.TrimSpace(egressURLPattern.ReplaceAllString(value, " "))
	if rest == "" {
		return
	}

	// A scalar that is ONLY a host — `registry: mirror.acme.io`, an ingress
	// rule's `- host: api.acme.io`. A sentence that happens to mention one is
	// not read unless the key says the value is a destination.
	host, _, ok := literalHost(rest)
	if ok && !seen[host] && isEgressHost(host) && !hasFileExtensionTLD(host) &&
		isCommonNetworkTLD(host) {
		record(egressSighting{
			Host: host, Source: source, Path: path, Line: line,
			Evidence: egressEvidenceConfig, KeyPath: keyPath,
		})

		return
	}

	if !egressDestinationKeys[key] {
		return
	}
	for _, h := range egressHostPattern.FindAllStringSubmatch(rest, -1) {
		host := normaliseHost(h[1])
		if seen[host] || !isEgressHost(host) || hasFileExtensionTLD(host) ||
			!isCommonNetworkTLD(host) {
			continue
		}
		seen[host] = true
		record(egressSighting{
			Host: host, Source: source, Path: path, Line: line,
			Evidence: egressEvidenceConfig, KeyPath: keyPath,
		})
	}
}
