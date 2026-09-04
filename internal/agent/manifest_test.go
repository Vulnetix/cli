package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writePayload builds a Write tool call proposing new content for a file.
func writePayload(t *testing.T, path, content string) Payload {
	t.Helper()
	in, err := json.Marshal(EditInput{FilePath: path, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return Payload{
		HookEventName: EventPreToolUse,
		ToolName:      "Write",
		ToolInput:     in,
	}
}

// TestManifestCandidatesAcrossFormats covers the edit path for every manifest
// format the walker detects, because a format that parses to nothing is a
// silent miss: the guard looks identical whether it checked and found nothing
// or never understood the file.
func TestManifestCandidatesAcrossFormats(t *testing.T) {
	cases := []struct {
		file   string
		before string
		after  string
		want   string
	}{
		{
			file:   "package.json",
			before: `{"name":"p","dependencies":{}}`,
			after:  `{"name":"p","dependencies":{"lodash":"4.17.20"}}`,
			want:   "lodash",
		},
		{
			file:   "go.mod",
			before: "module p\n\ngo 1.22\n",
			after:  "module p\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.6.0\n",
			want:   "github.com/gin-gonic/gin",
		},
		{
			file:   "requirements.txt",
			before: "# deps\n",
			after:  "# deps\nrequests==2.19.0\n",
			want:   "requests",
		},
		{
			file:   "Cargo.toml",
			before: "[package]\nname = \"p\"\nversion = \"0.1.0\"\n\n[dependencies]\n",
			after:  "[package]\nname = \"p\"\nversion = \"0.1.0\"\n\n[dependencies]\nsmallvec = \"0.6.0\"\n",
			want:   "smallvec",
		},
		{
			file:   "Gemfile",
			before: "source \"https://rubygems.org\"\n",
			after:  "source \"https://rubygems.org\"\ngem \"rack\", \"2.0.1\"\n",
			want:   "rack",
		},
		{
			file:   "composer.json",
			before: `{"name":"p/app","require":{"php":">=8.0"}}`,
			after:  `{"name":"p/app","require":{"php":">=8.0","monolog/monolog":"1.0.0"}}`,
			want:   "monolog/monolog",
		},
		{
			file:   "pom.xml",
			before: `<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId><artifactId>p</artifactId><version>1.0</version><dependencies></dependencies></project>`,
			after:  `<project><modelVersion>4.0.0</modelVersion><groupId>p</groupId><artifactId>p</artifactId><version>1.0</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`,
			// Maven names a package by its full coordinate, which is what VDB
			// is asked about.
			want: "org.apache.logging.log4j:log4j-core",
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.file)
			if err := os.WriteFile(path, []byte(tc.before), 0o644); err != nil {
				t.Fatal(err)
			}

			r := Runner{Policy: DefaultPolicy(), Root: dir}
			got := r.manifestCandidates(writePayload(t, path, tc.after))

			if len(got) == 0 {
				t.Fatalf("no candidates recovered from a %s that added %s", tc.file, tc.want)
			}
			found := false
			for _, c := range got {
				if c.Name == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("candidates %+v do not include %s", got, tc.want)
			}
		})
	}
}

// TestManifestEditReportsOnlyWhatChanged is what keeps the edit path liveable
// in a repository that already carries vulnerable dependencies.
func TestManifestEditReportsOnlyWhatChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	before := `{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.20","left-pad":"1.3.0"}}`
	if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}

	r := Runner{Policy: DefaultPolicy(), Root: dir}

	// An unrelated change to a manifest full of dependencies assesses none of
	// them.
	unrelated := `{"name":"p","version":"2.0.0","dependencies":{"lodash":"4.17.20","left-pad":"1.3.0"}}`
	if got := r.manifestCandidates(writePayload(t, path, unrelated)); len(got) != 0 {
		t.Fatalf("unrelated edit produced %+v, want nothing", got)
	}

	// Adding one assesses exactly that one.
	added := `{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.20","left-pad":"1.3.0","axios":"1.0.0"}}`
	got := r.manifestCandidates(writePayload(t, path, added))
	if len(got) != 1 || got[0].Name != "axios" {
		t.Fatalf("got %+v, want only axios", got)
	}

	// Changing one assesses exactly that one.
	bumped := `{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.21","left-pad":"1.3.0"}}`
	got = r.manifestCandidates(writePayload(t, path, bumped))
	if len(got) != 1 || got[0].Name != "lodash" || got[0].Version != "4.17.21" {
		t.Fatalf("got %+v, want only lodash@4.17.21", got)
	}
}

// TestManifestEditIsSilentOnAnUnreconstructableEdit keeps a partial edit whose
// anchor is absent from becoming a guess.
func TestManifestEditIsSilentOnAnUnreconstructableEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"p","dependencies":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	in, _ := json.Marshal(EditInput{
		FilePath:  path,
		OldString: `"this text is not in the file"`,
		NewString: `"lodash": "4.17.20"`,
	})
	p := Payload{HookEventName: EventPreToolUse, ToolName: "Edit", ToolInput: in}

	r := Runner{Policy: DefaultPolicy(), Root: dir}
	if got := r.manifestCandidates(p); len(got) != 0 {
		t.Fatalf("got %+v, want nothing when the edit cannot be reconstructed", got)
	}
}
