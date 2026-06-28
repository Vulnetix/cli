package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMalscanDefinitionsDir(t *testing.T) {
	t.Setenv("VULNETIX_MALSCAN_DEFS_DIR", "/custom/defs")
	if got := malscanDefinitionsDir(); got != "/custom/defs" {
		t.Errorf("env override: got %q, want /custom/defs", got)
	}

	t.Setenv("VULNETIX_MALSCAN_DEFS_DIR", "")
	got := malscanDefinitionsDir()
	if got == "" {
		t.Fatal("default dir must not be empty")
	}
	want := filepath.Join("vulnetix", "malscan", "definitions")
	if !strings.HasSuffix(got, want) {
		t.Errorf("default dir %q should end with %q", got, want)
	}
}

func TestMalscanFetchDefinitionsFlagRegistered(t *testing.T) {
	if malscanCmd.Flags().Lookup("fetch-definitions") == nil {
		t.Error("--fetch-definitions flag should be registered on malscan")
	}
}
