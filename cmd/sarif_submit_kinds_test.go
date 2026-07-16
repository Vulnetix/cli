package cmd

import "testing"

// A clean scan must still submit every ENABLED SARIF-family kind so the backend
// records a ScannerRun + snapshot (coverage). Before this, an enabled-but-clean
// kind was skipped and the category page showed no assessment at all.
func TestSarifSubmitKinds(t *testing.T) {
	kindsOf := func(sks []sarifScanKind) map[string]bool {
		m := map[string]bool{}
		for _, sk := range sks {
			m[sk.kind] = true
		}
		return m
	}

	// Only iac enabled → submit iac (even with zero findings), nothing else.
	got := kindsOf(sarifSubmitKinds(map[string]bool{"iac": true}))
	if !got["iac"] || len(got) != 1 {
		t.Errorf("iac-only: want {iac}, got %v", got)
	}

	// All four enabled → all four submit.
	all := kindsOf(sarifSubmitKinds(map[string]bool{"sast": true, "secrets": true, "iac": true, "oci": true}))
	for _, k := range []string{"sast", "secrets", "iac", "oci"} {
		if !all[k] {
			t.Errorf("all-enabled: missing %q in %v", k, all)
		}
	}

	// Nothing enabled → submit nothing (disabled scanners stay silent).
	if n := len(sarifSubmitKinds(map[string]bool{})); n != 0 {
		t.Errorf("none-enabled: want 0, got %d", n)
	}

	// Disabled kind is excluded even though others run.
	partial := kindsOf(sarifSubmitKinds(map[string]bool{"sast": true, "iac": false}))
	if partial["iac"] || !partial["sast"] {
		t.Errorf("partial: want {sast}, got %v", partial)
	}
}
