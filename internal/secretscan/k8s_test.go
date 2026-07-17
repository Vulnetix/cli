package secretscan

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestExpandKubernetesSecrets(t *testing.T) {
	// The canonical AWS documentation example key: realistic shape without
	// tripping push-protection secret scanners.
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	manifest := `apiVersion: v1
kind: Secret
metadata:
  name: creds
type: Opaque
data:
  aws: ` + base64.StdEncoding.EncodeToString([]byte("aws_access_key_id="+awsKey)) + `
  blob: ` + base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xff}) + `
  broken: not-base64!!!
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: notasecret
data:
  cfg: ` + base64.StdEncoding.EncodeToString([]byte("harmless")) + `
`
	out := ExpandKubernetesSecrets("k8s/secret.yaml", manifest)
	if len(out) != 1 {
		t.Fatalf("got %d entries, want 1 (only the printable Secret value): %v", len(out), out)
	}
	key := K8sSecretPrefix + "k8s/secret.yaml/aws"
	if !strings.Contains(out[key], awsKey) {
		t.Errorf("decoded value missing: %q", out[key])
	}
}

func TestExpandKubernetesSecretsNonSecretYAML(t *testing.T) {
	if out := ExpandKubernetesSecrets("d.yaml", "apiVersion: apps/v1\nkind: Deployment\nspec: {}\n"); out != nil {
		t.Errorf("non-Secret YAML expanded: %v", out)
	}
	// Malformed sibling must not hide a valid Secret document.
	manifest := "\t bad: [yaml\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: s}\ndata:\n  k: " +
		base64.StdEncoding.EncodeToString([]byte("token=abc123")) + "\n"
	out := ExpandKubernetesSecrets("m.yaml", manifest)
	if len(out) != 1 {
		t.Errorf("valid Secret lost next to malformed doc: %v", out)
	}
}
