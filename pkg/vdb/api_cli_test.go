package vdb

import (
	"encoding/json"
	"testing"
)

func TestCliEnv_Marshaling(t *testing.T) {
	env := CliEnv{
		CliVersion: "1.0.0",
		Platform:   "linux",
		Arch:       "amd64",
		OS:         "linux",
		Hostname:   "test-host",
		Shell:      "/bin/bash",
		MemoryPath: "/tmp/.vulnetix/memory.yaml",
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded CliEnv
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.CliVersion != "1.0.0" {
		t.Errorf("expected '1.0.0', got %q", decoded.CliVersion)
	}
}

func TestCliEnv_EmptyJSON(t *testing.T) {
	var env CliEnv
	data, _ := json.Marshal(env)
	var decoded CliEnv
	json.Unmarshal(data, &decoded)
}

func TestCliGitContext(t *testing.T) {
	ctx := CliGitContext{
		Branch: "main",
		Commit: "abc123",
		Author: "test",
	}
	if ctx.Branch != "main" || ctx.Commit != "abc123" {
		t.Errorf("unexpected values: %+v", ctx)
	}
}

func TestCliPackageMgr(t *testing.T) {
	pm := CliPackageMgr{
		Ecosystem: "npm",
		Manifest:  "package.json",
		IsLock:    false,
	}
	if pm.Ecosystem != "npm" || pm.Manifest != "package.json" {
		t.Errorf("unexpected values: %+v", pm)
	}
}

func TestCliLicenseHit(t *testing.T) {
	l := CliLicenseHit{
		SPDXID: "MIT",
		Name:   "MIT License",
	}
	if l.SPDXID != "MIT" {
		t.Errorf("expected 'MIT', got %q", l.SPDXID)
	}
}

func TestCliManifestMetadata(t *testing.T) {
	m := CliManifestMetadata{
		Path:      "package.json",
		Ecosystem: "npm",
		IsLock:    false,
	}
	if m.Path != "package.json" || m.Ecosystem != "npm" {
		t.Errorf("unexpected values: %+v", m)
	}
}

func TestCliSBOMToolMetadata(t *testing.T) {
	m := CliSBOMToolMetadata{
		ToolName:    "vulnetix",
		ToolVersion: "1.0.0",
		ToolVendor:  "Vulnetix",
	}
	if m.ToolName != "vulnetix" {
		t.Errorf("expected 'vulnetix', got %q", m.ToolName)
	}
}

func TestCliPMCapability(t *testing.T) {
	c := CliPMCapability{
		Ecosystem:      "npm",
		CapabilityName: "npm",
		Supported:      true,
		Detected:       true,
		Confidence:     1.0,
	}
	if c.Ecosystem != "npm" || c.CapabilityName != "npm" || !c.Supported {
		t.Errorf("unexpected values: %+v", c)
	}
}

func TestCliResponseEnvelope(t *testing.T) {
	raw := cliResponseEnvelope{
		Meta: CliResponseMeta{
			Tier:            "community",
			EndpointVersion: "v1",
			RequestID:       "req-123",
		},
		Data: json.RawMessage(`{"key":"value"}`),
	}
	if raw.Meta.Tier != "community" {
		t.Errorf("expected 'community', got %q", raw.Meta.Tier)
	}
}

func TestCliResponse(t *testing.T) {
	resp := CliResponse[string]{
		Meta: CliResponseMeta{Tier: "pro"},
		Data: "test-data",
	}
	if resp.Meta.Tier != "pro" || resp.Data != "test-data" {
		t.Errorf("unexpected values: %+v", resp)
	}
}

func TestCliSCAOptions(t *testing.T) {
	opts := CliSCAOptions{
		IncludeCooldown:   true,
		IncludeVersionLag: false,
		IncludeEOL:        true,
	}
	if !opts.IncludeCooldown || opts.IncludeVersionLag || !opts.IncludeEOL {
		t.Errorf("unexpected values: %+v", opts)
	}
}
