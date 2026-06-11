package triage

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/versions"
)

func TestCheckAffected(t *testing.T) {
	entry := func(name, eco string, vers []interface{}, defaultStatus string) map[string]interface{} {
		m := map[string]interface{}{
			"packageName": name,
			"ecosystem":   eco,
		}
		if vers != nil {
			m["versions"] = vers
		}
		if defaultStatus != "" {
			m["defaultStatus"] = defaultStatus
		}
		return m
	}
	resp := func(entries ...interface{}) map[string]interface{} {
		return map[string]interface{}{"affected": entries}
	}

	cases := []struct {
		name string
		resp map[string]interface{}
		pkg  string
		eco  string
		ver  string
		want versions.Status
	}{
		{
			name: "nil response is unknown",
			resp: nil,
			pkg:  "lodash", eco: "npm", ver: "1.0.0",
			want: versions.StatusUnknown,
		},
		{
			name: "legacy bool-shaped affected true maps to affected",
			resp: map[string]interface{}{"affected": true},
			pkg:  "lodash", eco: "npm", ver: "1.0.0",
			want: versions.StatusAffected,
		},
		{
			name: "legacy bool-shaped affected false maps to unaffected",
			resp: map[string]interface{}{"affected": false},
			pkg:  "lodash", eco: "npm", ver: "1.0.0",
			want: versions.StatusUnaffected,
		},
		{
			name: "exact unaffected match beats affected range",
			resp: resp(entry("jwt", "npm", []interface{}{
				map[string]interface{}{"version": "0", "status": "affected", "lessThan": "2.0.0"},
				map[string]interface{}{"version": "1.5.0", "status": "unaffected"},
			}, "")),
			pkg: "jwt", eco: "npm", ver: "1.5.0",
			want: versions.StatusUnaffected,
		},
		{
			name: "version inside affected range",
			resp: resp(entry("jwt", "npm", []interface{}{
				map[string]interface{}{"version": "1.0.0", "status": "affected", "lessThan": "2.0.0"},
			}, "")),
			pkg: "jwt", eco: "npm", ver: "1.5.0",
			want: versions.StatusAffected,
		},
		{
			name: "no version data stays unknown",
			resp: resp(entry("jwt", "npm", nil, "")),
			pkg:  "jwt", eco: "npm", ver: "1.5.0",
			want: versions.StatusUnknown,
		},
		{
			name: "package name mismatch stays unknown",
			resp: resp(entry("other", "npm", []interface{}{
				map[string]interface{}{"version": "1.5.0", "status": "affected"},
			}, "")),
			pkg: "jwt", eco: "npm", ver: "1.5.0",
			want: versions.StatusUnknown,
		},
		{
			name: "default status unaffected applies when nothing matches",
			resp: resp(entry("jwt", "npm", []interface{}{
				map[string]interface{}{"version": "1.0.0", "status": "affected", "lessThan": "1.2.0"},
			}, "unaffected")),
			pkg: "jwt", eco: "npm", ver: "3.0.0",
			want: versions.StatusUnaffected,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checkAffected(c.resp, c.pkg, c.eco, c.ver); got != c.want {
				t.Errorf("checkAffected = %v, want %v", got, c.want)
			}
		})
	}
}
