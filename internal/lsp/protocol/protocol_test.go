package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The JSON struct tags on these hand-written types ARE the LSP wire contract,
// but they are only exercised indirectly through internal/lsp/conformance_test.go.
// These tests pin them in-package, so a tag typo, a missing omitempty, or a
// drifted constant fails here rather than in an editor.
//
// They use stdlib testing + reflect rather than testify, so the package's test
// binary does not pull in net (via testify's HTTP assertions) and therefore
// builds without a C compiler.

func TestMarshalUnmarshalRoundTrips(t *testing.T) {
	processID := 42
	cvss := 9.8

	diag := Diagnostic{
		Range: Range{
			Start: Position{Line: 3, Character: 4},
			End:   Position{Line: 3, Character: 10},
		},
		Severity: SeverityError,
		Code:     "vuln-001",
		CodeDescription: &CodeDescription{
			Href: "https://docs.vulnetix.com/rules/vuln-001",
		},
		Source:  "vulnetix-sca",
		Message: "vulnerable dependency",
		Tags:    []int{TagUnnecessary, TagDeprecated},
		RelatedInformation: []DiagnosticRelatedInformation{
			{
				Location: Location{
					URI:   "file:///go.mod",
					Range: Range{Start: Position{Line: 1, Character: 1}, End: Position{Line: 1, Character: 5}},
				},
				Message: "dependency",
			},
		},
		Data: json.RawMessage(`{"findingId":"a1","confidence":0.9}`),
	}

	finding := Finding{
		ID:       "sca:CVE-2024-0001:pkg:golang/example.com/lib@1.0.0",
		Tool:     "vulnetix-sca",
		RuleID:   "CVE-2024-0001",
		RuleName: "known vulnerability",
		Title:    "vulnerable dependency",
		Message:  "example.com/lib 1.0.0 is vulnerable",
		Severity: "critical",
		Level:    "error",
		Location: FindingLocation{
			URI:              "file:///go.mod",
			Range:            Range{Start: Position{Line: 2, Character: 0}, End: Position{Line: 2, Character: 8}},
			AnchorConfidence: AnchorExact,
		},
		RelatedLocations: []RelatedLocation{
			{URI: "file:///go.sum", Range: Range{Start: Position{Line: 5, Character: 0}, End: Position{Line: 5, Character: 4}}, Message: "lock entry"},
		},
		Package: &PackageInfo{
			Purl:        "pkg:golang/example.com/lib@1.0.0",
			Name:        "example.com/lib",
			Version:     "1.0.0",
			Ecosystem:   "go",
			Direct:      true,
			Scope:       "runtime",
			IsEOL:       true,
			IsMalicious: false,
			PathCount:   2,
		},
		Vuln: &VulnInfo{
			ID:              "CVE-2024-0001",
			Aliases:         []string{"GHSA-aaaa-bbbb-cccc"},
			CVSS:            &cvss,
			SSVC:            "act",
			InCisaKev:       true,
			ExploitMaturity: "functional",
			CWEs:            []int{79},
			Reachability:    "reachable",
		},
		Status: "open",
		Vex: &VexInfo{
			Status:          "not_affected",
			Justification:   "vulnerable_code_not_present",
			ActionStatement: "none",
		},
		Suppression: &SuppressionInfo{
			Kind:      "cli",
			Reason:    "false positive",
			ExpiresAt: "2026-12-31",
		},
		HelpURI:      "https://docs.vulnetix.com/findings/CVE-2024-0001",
		FixAvailable: true,
		Snippet:      "github.com/example/lib v1.0.0",
	}

	gate := &GateResult{
		Breached: true,
		Reasons:  []string{"critical finding", "malicious dependency"},
	}

	scan := ScanWorkspaceResult{
		ProtocolVersion: ProtocolVersion,
		ScanID:          "scan-123",
		DurationMS:      1234,
		Counts: ScanCounts{
			BySeverity: map[string]int{"critical": 1, "high": 2},
			ByTool:     map[string]int{"vulnetix-sca": 3},
			Total:      3,
		},
		Artifacts: ScanArtifacts{
			SBOM:   "sbom.cdx.json",
			SARIF:  "scan.sarif",
			Memory: "memory.yaml",
		},
		Gate:         gate,
		Degradations: []string{"secrets: git history unavailable"},
	}

	initParams := InitializeParams{
		ProcessID:  &processID,
		RootURI:    "file:///workspace",
		ClientInfo: &Client{Name: "vscode", Version: "1.90.0"},
		InitializationOptions: json.RawMessage(
			`{"vulnetix":{"scan":{"debounceMs":250}}}`,
		),
		Capabilities: ClientCaps{
			Workspace: struct {
				Configuration          bool `json:"configuration,omitempty"`
				WorkspaceFolders       bool `json:"workspaceFolders,omitempty"`
				DidChangeConfiguration struct {
					DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
				} `json:"didChangeConfiguration"`
			}{
				Configuration:    true,
				WorkspaceFolders: true,
				DidChangeConfiguration: struct {
					DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
				}{DynamicRegistration: true},
			},
			TextDocument: struct {
				PublishDiagnostics struct {
					RelatedInformation bool `json:"relatedInformation,omitempty"`
					DataSupport        bool `json:"dataSupport,omitempty"`
					TagSupport         struct {
						ValueSet []int `json:"valueSet,omitempty"`
					} `json:"tagSupport"`
				} `json:"publishDiagnostics"`
			}{
				PublishDiagnostics: struct {
					RelatedInformation bool `json:"relatedInformation,omitempty"`
					DataSupport        bool `json:"dataSupport,omitempty"`
					TagSupport         struct {
						ValueSet []int `json:"valueSet,omitempty"`
					} `json:"tagSupport"`
				}{
					RelatedInformation: true,
					DataSupport:        true,
					TagSupport: struct {
						ValueSet []int `json:"valueSet,omitempty"`
					}{ValueSet: []int{TagUnnecessary, TagDeprecated}},
				},
			},
			Window: struct {
				WorkDoneProgress bool `json:"workDoneProgress,omitempty"`
			}{WorkDoneProgress: true},
			General: struct {
				PositionEncodings []string `json:"positionEncodings,omitempty"`
			}{PositionEncodings: []string{"utf-16", "utf-8"}},
		},
		WorkspaceFolders: []Folder{{URI: "file:///workspace", Name: "workspace"}},
		Trace:            "off",
	}

	tests := []struct {
		name  string
		shape any
	}{
		{name: "Diagnostic", shape: diag},
		{name: "Finding", shape: finding},
		{name: "ScanWorkspaceResult", shape: scan},
		{name: "InitializeParams", shape: initParams},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.shape)
			if err != nil {
				t.Fatalf("marshal %T: %v", tt.shape, err)
			}

			// A fresh value of the same dynamic type is the unmarshal target, so
			// the round trip must preserve every field including nested and
			// omitted-pointer shapes.
			out := reflect.New(reflect.TypeOf(tt.shape)).Interface()
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatalf("unmarshal %T: %v", tt.shape, err)
			}
			got := reflect.ValueOf(out).Elem().Interface()
			if !reflect.DeepEqual(tt.shape, got) {
				t.Fatalf("round trip mismatch for %T:\n got: %#v\nwant: %#v", tt.shape, got, tt.shape)
			}
		})
	}
}

func TestOmitEmpty(t *testing.T) {
	tests := []struct {
		name    string
		shape   any
		absent  []string
		present []string
		nulls   []string
	}{
		{
			name:    "ScanWorkspaceResult without gate",
			shape:   ScanWorkspaceResult{ProtocolVersion: ProtocolVersion, ScanID: "scan-1", DurationMS: 10, Counts: ScanCounts{Total: 0}},
			absent:  []string{"gate"},
			present: []string{"protocolVersion", "scanId"},
		},
		{
			name:    "InitializeParams without nullable fields",
			shape:   InitializeParams{Capabilities: ClientCaps{}},
			absent:  []string{"clientInfo", "initializationOptions"},
			present: []string{"capabilities"},
			// ProcessID is *int with no omitempty on purpose: LSP allows an
			// explicit null here, so a nil pointer is pinned as null, not omitted.
			nulls: []string{"processId"},
		},
		{
			name:    "Finding without optional findings data",
			shape:   Finding{ID: "a1", Tool: "vulnetix-sca", Message: "m", Severity: "high", Location: FindingLocation{URI: "file:///x", Range: Range{}}},
			absent:  []string{"package", "vuln", "vex", "suppression"},
			present: []string{"id", "tool", "message", "severity", "location"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.shape)
			if err != nil {
				t.Fatalf("marshal %T: %v", tt.shape, err)
			}

			var obj map[string]json.RawMessage
			if err := json.Unmarshal(b, &obj); err != nil {
				t.Fatalf("unmarshal into map: %v", err)
			}

			for _, key := range tt.absent {
				if _, ok := obj[key]; ok {
					t.Errorf("field %q should be omitted", key)
				}
			}
			for _, key := range tt.present {
				if _, ok := obj[key]; !ok {
					t.Errorf("field %q should be present", key)
				}
			}
			for _, key := range tt.nulls {
				raw, ok := obj[key]
				if !ok {
					t.Errorf("field %q should be present", key)
					continue
				}
				if string(raw) != "null" {
					t.Errorf("field %q should be JSON null, got %s", key, raw)
				}
			}
		})
	}
}

func TestContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"ProtocolVersion", ProtocolVersion, 1},
		{"ServerName", ServerName, "vulnetix"},
		{"CodeRequestCancelled", CodeRequestCancelled, -32800},
		{"CodeContentModified", CodeContentModified, -32801},
		{"SeverityError", SeverityError, 1},
		{"SeverityWarning", SeverityWarning, 2},
		{"SeverityInformation", SeverityInformation, 3},
		{"SeverityHint", SeverityHint, 4},
		{"MethodServerInfo", MethodServerInfo, "vulnetix/serverInfo"},
		{"MethodScanWorkspace", MethodScanWorkspace, "vulnetix/scanWorkspace"},
		{"MethodScanStatus", MethodScanStatus, "vulnetix/scanStatus"},
		{"MethodFindings", MethodFindings, "vulnetix/findings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}
