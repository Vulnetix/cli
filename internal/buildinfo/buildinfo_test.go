package buildinfo

import "testing"

// buildinfo_test.go pins the Set branching: the default version survives an
// empty one, a non-empty one overwrites it, and Commit/BuildDate are assigned
// unconditionally. Version, Commit and BuildDate are package-level vars, so
// every case saves and restores them rather than running in parallel.

func TestDefaults(t *testing.T) {
	if Version != "0.0.0-unknown" {
		t.Errorf("Version = %q, want %q", Version, "0.0.0-unknown")
	}
	if Commit != "" {
		t.Errorf("Commit = %q, want empty", Commit)
	}
	if BuildDate != "" {
		t.Errorf("BuildDate = %q, want empty", BuildDate)
	}
}

func TestSet(t *testing.T) {
	tests := []struct {
		name                    string
		version, commit, build  string
		wantVersion, wantCommit string
		wantBuild               string
	}{
		{
			name:        "empty version keeps default and assigns commit and build date",
			version:     "",
			commit:      "c",
			build:       "d",
			wantVersion: "0.0.0-unknown",
			wantCommit:  "c",
			wantBuild:   "d",
		},
		{
			name:        "non-empty version overwrites all three",
			version:     "v1.2.3",
			commit:      "c",
			build:       "d",
			wantVersion: "v1.2.3",
			wantCommit:  "c",
			wantBuild:   "d",
		},
		{
			name:        "empty commit and build date clear them while keeping version",
			version:     "v1.2.3",
			commit:      "",
			build:       "",
			wantVersion: "v1.2.3",
			wantCommit:  "",
			wantBuild:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldVersion, oldCommit, oldBuild := Version, Commit, BuildDate
			t.Cleanup(func() {
				Version, Commit, BuildDate = oldVersion, oldCommit, oldBuild
			})

			Set(tt.version, tt.commit, tt.build)

			if Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", Version, tt.wantVersion)
			}
			if Commit != tt.wantCommit {
				t.Errorf("Commit = %q, want %q", Commit, tt.wantCommit)
			}
			if BuildDate != tt.wantBuild {
				t.Errorf("BuildDate = %q, want %q", BuildDate, tt.wantBuild)
			}
		})
	}
}
