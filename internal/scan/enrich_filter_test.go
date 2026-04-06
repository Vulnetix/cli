package scan

import "testing"

func TestCheckAffectedResponse_VersionRangeFiltering(t *testing.T) {
	tests := []struct {
		name         string
		data         map[string]interface{}
		pkgName      string
		installedVer string
		ecosystem    string
		wantAffected bool
		wantMethod   string
	}{
		{
			name:         "no affected data assumes affected",
			data:         map[string]interface{}{},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "no-data",
		},
		{
			name: "version in range is affected",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "name+version",
		},
		{
			name: "version outside range is not affected",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.21",
			ecosystem:    "npm",
			wantAffected: false,
			wantMethod:   "name+version",
		},
		{
			name: "multiple ranges — affected by second range",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 3.0.0, < 3.10.2",
					},
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "name+version",
		},
		{
			name: "multiple ranges — not affected by any",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 3.0.0, < 3.10.2",
					},
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.21",
			ecosystem:    "npm",
			wantAffected: false,
			wantMethod:   "name+version",
		},
		{
			name: "affected entries exist but none match package — not affected",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "other-package",
						"ecosystem":    "npm",
						"versionRange": ">= 1.0.0, < 2.0.0",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: false,
			wantMethod:   "unmatched",
		},
		{
			name: "product field used as name fallback — affected",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"product":      "lodash",
						"vendor":       "lodash",
						"cpe":          "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "name+version",
		},
		{
			name: "CPE-only match — no packageName or product, matched via cpe string",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"vendor":       "lodash_project",
						"cpe":          "cpe:2.3:a:lodash_project:lodash:*:*:*:*:*:*:*:*",
						"versionRange": ">= 4.0.0, < 4.17.21",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.21",
			ecosystem:    "npm",
			wantAffected: false,
			wantMethod:   "cpe+version",
		},
		{
			name: "CPE match via suffix — namespaced package",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"vendor":       "apache",
						"product":      "log4j-core",
						"cpe":          "cpe:2.3:a:apache:log4j-core:*:*:*:*:*:*:*:*",
						"versionRange": ">= 2.0.0, < 2.17.1",
					},
				},
			},
			pkgName:      "org.apache.logging.log4j:log4j-core",
			installedVer: "2.14.0",
			ecosystem:    "maven",
			wantAffected: true,
			wantMethod:   "cpe+version",
		},
		{
			name: "wildcard range defers to fix check",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName":  "lodash",
						"ecosystem":    "npm",
						"versionRange": "*",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "name+wildcard",
		},
		{
			name: "CPE wildcard range defers to fix check",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"vendor":       "lodash_project",
						"cpe":          "cpe:2.3:a:lodash_project:lodash:*:*:*:*:*:*:*:*",
						"versionRange": "*",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "cpe+wildcard",
		},
		{
			name: "name match without version range — assume affected",
			data: map[string]interface{}{
				"affected": []interface{}{
					map[string]interface{}{
						"packageName": "lodash",
						"ecosystem":   "npm",
					},
				},
			},
			pkgName:      "lodash",
			installedVer: "4.17.20",
			ecosystem:    "npm",
			wantAffected: true,
			wantMethod:   "name-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, affected, method := checkAffectedResponse(tt.data, tt.pkgName, tt.installedVer, tt.ecosystem)
			if affected != tt.wantAffected {
				t.Errorf("affected = %v, want %v", affected, tt.wantAffected)
			}
			if method != tt.wantMethod {
				t.Errorf("matchMethod = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}
