package secretscan

import (
	"encoding/base64"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// K8sSecretPrefix is the synthetic path prefix for decoded Kubernetes Secret
// values. Findings under __k8s_secret__/<file>/<key> point back at the
// manifest file and data key that carried the base64-encoded value.
const K8sSecretPrefix = "__k8s_secret__/"

// maxDecodedSecretValue caps a single decoded data value; anything larger is
// a blob (certificate bundle, keystore), not a credential string.
const maxDecodedSecretValue = 1 << 20 // 1 MiB

// ExpandKubernetesSecrets base64-decodes the `data:` entries of Kubernetes
// Secret documents in a YAML file so the secret rules can scan the decoded
// values — base64 encoding otherwise evades every line-regex rule.
//
// Returned map keys are synthetic paths (__k8s_secret__/<relPath>/<key>).
// Only `kind: Secret` documents participate; decode failures and oversized
// or non-printable values are skipped silently (skip-and-continue, like the
// rest of the scanner). `stringData:` is already plaintext inside the file
// content and needs no expansion.
func ExpandKubernetesSecrets(relPath, content string) map[string]string {
	// Cheap gate before any YAML work.
	if !strings.Contains(content, "kind:") || !strings.Contains(content, "Secret") || !strings.Contains(content, "data:") {
		return nil
	}
	var out map[string]string
	for _, doc := range splitYAMLDocs(content) {
		var m struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			continue
		}
		if m.Kind != "Secret" || len(m.Data) == 0 {
			continue
		}
		for key, encoded := range m.Data {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
			if err != nil || len(decoded) == 0 || len(decoded) > maxDecodedSecretValue {
				continue
			}
			if !printableText(decoded) {
				continue // binary blob (keystore, DER cert) — not a scannable credential string
			}
			if out == nil {
				out = map[string]string{}
			}
			out[K8sSecretPrefix+relPath+"/"+key] = string(decoded)
		}
	}
	return out
}

// splitYAMLDocs splits a YAML stream on `---` separators. Per-document
// decoding lets valid documents survive a malformed sibling (yaml.Decoder
// cannot recover mid-stream).
func splitYAMLDocs(content string) []string {
	var docs []string
	var current []string
	flush := func() {
		if len(current) == 0 {
			return
		}
		doc := strings.Join(current, "\n")
		if strings.TrimSpace(doc) != "" {
			docs = append(docs, doc)
		}
		current = nil
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()
	return docs
}

// printableText reports whether decoded bytes look like text worth scanning.
func printableText(data []byte) bool {
	printable := 0
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b >= 0x20 && b < 0x7f || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable*10 >= len(data)*7 // >= 70% printable
}
