package cmd

import "testing"

func TestSpecializedRuleKinds(t *testing.T) {
	cases := map[string][]string{
		"containers": {"oci", "container"},
		"secrets":    {"secrets"},
		"iac":        {"iac"},
		"sast":       {"sast"},
		"scan":       nil,
		"sca":        nil,
		"":           nil,
	}
	for name, want := range cases {
		got := specializedRuleKinds(name)
		if len(got) != len(want) {
			t.Fatalf("%s: got %v want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v want %v", name, got, want)
			}
		}
	}
}

// regoSrc builds a minimal rule module body with the given id and kind. An
// empty id models a shared library (helper) module.
func regoSrc(id, kind string) string {
	if id == "" {
		// library: no metadata.id
		return `package lib
helper(x) := x`
	}
	return `package r
metadata := {"id": "` + id + `", "kind": "` + kind + `"}`
}

func TestFilterModulesToKinds_ContainerScope(t *testing.T) {
	modules := map[string]string{
		"rules/vnx-docker-001.rego":      regoSrc("VNX-DOCKER-001", "oci"),
		"ext/community/container-1.rego": regoSrc("COMM-CONTAINER-1", "container"),
		"ext/kics/iac-1.rego":            regoSrc("KICS-IAC-1", "iac"),
		"ext/spego/api-1.rego":           regoSrc("SPEGO-API-1", "api"),
		"ext/vnx-sec-1.rego":             regoSrc("VNX-SEC-1", "secrets"),
		"ext/community/_lib/docker.rego": regoSrc("", ""), // shared library, must be kept
	}
	got := filterModulesToKinds(modules, []string{"oci", "container"})

	mustKeep := []string{
		"rules/vnx-docker-001.rego",
		"ext/community/container-1.rego",
		"ext/community/_lib/docker.rego", // dependency library retained
	}
	for _, k := range mustKeep {
		if _, ok := got[k]; !ok {
			t.Fatalf("expected %s to be kept; got=%v", k, keys(got))
		}
	}
	mustDrop := []string{
		"ext/kics/iac-1.rego",
		"ext/spego/api-1.rego",
		"ext/vnx-sec-1.rego",
	}
	for _, k := range mustDrop {
		if _, ok := got[k]; ok {
			t.Fatalf("expected %s to be dropped; got=%v", k, keys(got))
		}
	}
}

func TestFilterModulesToKinds_EmptyKindsReturnsAll(t *testing.T) {
	modules := map[string]string{"a": regoSrc("A", "iac")}
	got := filterModulesToKinds(modules, nil)
	if len(got) != 1 {
		t.Fatalf("expected passthrough with no kinds, got %v", keys(got))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
