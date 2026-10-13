package cmd

import "testing"

func TestDisplayVersionHasOneLeadingV(t *testing.T) {
	saved := version
	defer func() { version = saved }()
	for in, want := range map[string]string{"v3.115.5": "v3.115.5", "3.115.5": "v3.115.5", "1.0.0": "v1.0.0"} {
		version = in
		if got := displayVersion(); got != want {
			t.Errorf("displayVersion() with version %q = %q, want %q", in, got, want)
		}
	}
}
