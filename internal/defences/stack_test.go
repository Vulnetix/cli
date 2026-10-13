package defences

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInferStack(t *testing.T) {
	root := t.TempDir()
	write(t, root, "infra/waf.tf", "resource \"x\" \"y\" {}\nresource \"aws_wafv2_web_acl\" \"main\" {}\n")
	write(t, root, "docker/modsec/rules.conf", "SecRuleEngine On\n")
	write(t, root, "deploy/nginx.conf", "server {}\n")
	// Must be ignored: dependency trees are not the user's enforcement points.
	write(t, root, "node_modules/x/waf.tf", "aws_wafv2_web_acl\n")
	write(t, root, "README.md", "mentions aws_wafv2_web_acl in prose")

	got := InferStack(root)

	if h, ok := got[KindAWSWAF]; !ok || h.Where() != "infra/waf.tf:2" {
		t.Fatalf("aws waf: %+v", got[KindAWSWAF])
	}
	if h, ok := got[KindModSec]; !ok || h.File != "docker/modsec/rules.conf" {
		t.Fatalf("modsecurity: %+v", got[KindModSec])
	}
	if _, ok := got[KindNginx]; !ok {
		t.Fatal("nginx.conf should be found")
	}
	if _, ok := got[KindCloudflare]; ok {
		t.Fatal("nothing suggests cloudflare")
	}
	if len(got) != 3 {
		t.Fatalf("expected exactly three hints, got %+v", got)
	}
}
