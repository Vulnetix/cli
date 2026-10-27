package sast

import "testing"

func TestRuleAppliesToFile(t *testing.T) {
	cases := []struct {
		name  string
		langs []string
		path  string
		want  bool
	}{
		{"no languages is universal", nil, "docs/readme.md", true},
		{"generic is universal", []string{"generic"}, "docs/readme.md", true},
		{"rule file never matches a language rule", []string{"node"}, "internal/sast/rules/vnx-node-012.rego", false},
		{"documentation never matches a language rule", []string{"go"}, "website/content/docs/sast-rules/vnx-go-014.md", false},
		{"own language applies", []string{"go"}, "cmd/root.go", true},
		{"node rule applies to ts", []string{"node"}, "src/app.ts", true},
		{"javascript rule skips a go file", []string{"node"}, "cmd/root_test.go", false},
		{"python rule skips a java file", []string{"python"}, "A.java", false},
		{"one of several languages is enough", []string{"python", "node"}, "x.js", true},
		{"html hosts inline javascript", []string{"node"}, "website/layouts/partials/head.html", true},
		{"vue hosts inline javascript", []string{"node"}, "src/App.vue", true},
		{"php templates host html and sql", []string{"php"}, "views/list.phtml", true},
		{"config types are not claimed by a language", []string{"node"}, "config/app.yaml", true},
		{"an unmodelled language fails open", []string{"cobol"}, "x.go", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ruleAppliesToFile(c.langs, c.path); got != c.want {
				t.Fatalf("ruleAppliesToFile(%v, %q) = %v, want %v", c.langs, c.path, got, c.want)
			}
		})
	}
}

func TestFindingAppliesSkipsRulePolicy(t *testing.T) {
	sast := &RuleMetadata{Kind: "sast"}
	if findingApplies(sast, "internal/sast/rules/vnx-614.rego", "") {
		t.Fatal("a sast rule must not report a .rego policy file")
	}
	if !findingApplies(sast, "cmd/root.go", "") {
		t.Fatal("an unscoped sast rule applies to ordinary source")
	}
	secrets := &RuleMetadata{Kind: "secrets"}
	if !findingApplies(secrets, "policy/auth.rego", "") {
		t.Fatal("a secret committed in a policy file is still a secret")
	}
}

func TestFindingAppliesProseAndJSON(t *testing.T) {
	generic := &RuleMetadata{Kind: "sast"}
	if findingApplies(generic, "README.md", "") {
		t.Fatal("a source rule with no declared languages must not report a README snippet")
	}
	docs := &RuleMetadata{Kind: "sast", Tags: []string{"documentation"}}
	if !findingApplies(docs, "docs/design.md", "") {
		t.Fatal("a rule tagged documentation is about prose and must still apply to it")
	}
	if findingApplies(&RuleMetadata{Kind: "sast", Languages: []string{"python", "go", "java"}}, "schemas/cyclonedx.schema.json", "") {
		t.Fatal("a Python/Go/Java rule must not report a value inside a JSON schema")
	}
	if !findingApplies(&RuleMetadata{Kind: "sast", Languages: []string{"node"}}, "package.json", "") {
		t.Fatal("JSON is configuration for JavaScript tooling and stays in scope for node rules")
	}
	if !findingApplies(&RuleMetadata{Kind: "sast", Languages: []string{"csharp"}}, "appsettings.json", "") {
		t.Fatal("JSON is configuration for .NET and stays in scope for csharp rules")
	}
	if !findingApplies(&RuleMetadata{Kind: "sast"}, "config/app.json", "") {
		t.Fatal("a rule that declares no languages is universal and must still see JSON")
	}
}

func TestFindingAppliesSkipsCommentLines(t *testing.T) {
	m := &RuleMetadata{Kind: "sast"}
	for _, s := range []string{"// md5.Sum(x)", "  /* eval(x) */", " * eval(x)", "# curl | sh", "\t// token := os.Getenv()"} {
		if findingApplies(m, "a.go", s) {
			t.Fatalf("a sast rule must not report a comment line: %q", s)
		}
	}
	for _, s := range []string{"/* 😀 */ return eval(expr);", "x := md5.Sum(b) // weak", "#include <openssl/md5.h>", "#!/bin/sh", "*p = 0", "result := a * b"} {
		if !findingApplies(m, "a.go", s) {
			t.Fatalf("code must still be reported: %q", s)
		}
	}
	if !findingApplies(&RuleMetadata{Kind: "sast", Tags: []string{"comments"}}, "a.go", "// TODO: fix auth") {
		t.Fatal("a rule about comments reads comments")
	}
	if !findingApplies(&RuleMetadata{Kind: "secrets"}, "a.go", "// password = hunter2") {
		t.Fatal("a secret in a comment is still a secret")
	}
}

func TestSyntheticContentReachesOnlySecretsRules(t *testing.T) {
	in := &ScanInput{
		FileSet: map[string]bool{"app.py": true, "logo.png": true},
		FileContents: map[string]string{
			"app.py":                         "import os",
			"__binary_strings__/logo.png":    "IHDR junk",
			"__exif__/logo.png":              "Make: x",
			"__git_history__/abc123/app.py":  "old",
			"__k8s_secret__/s.yaml/password": "hunter2",
		},
	}
	secrets := scopeOf(`metadata := {"kind": "secrets"}`)
	if got := scopedInput(in, secrets); got != in {
		t.Fatalf("a secrets rule must see the whole input, got %d entries", len(got.FileContents))
	}
	for _, src := range []string{`metadata := {"kind": "iac"}`, `metadata := {"kind": "sast"}`, `metadata := {"kind": "sast", "languages": ["python"]}`} {
		got := scopedInput(in, scopeOf(src))
		if len(got.FileContents) != 1 || got.FileContents["app.py"] == "" {
			t.Errorf("%s: file_contents = %v, want only app.py", src, got.FileContents)
		}
	}
	plain := &ScanInput{FileContents: map[string]string{"main.tf": "resource"}}
	if got := scopedInput(plain, scopeOf(`metadata := {"kind": "iac"}`)); got != plain {
		t.Error("a universal rule with no synthetic content should share the input, not copy it")
	}
}
