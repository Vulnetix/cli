package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/internal/platformiac"
	configschemas "github.com/vulnetix/config-schemas"
)

// Every kind the embedded config-schemas release knows is listed, has a
// schema `config schema` prints, and validates its own examples, so a newer
// release works without a CLI change.
func TestEveryReleasedKindListsPrintsAndValidates(t *testing.T) {
	kinds := platformiac.Kinds()
	if len(kinds) < 57 {
		t.Fatalf("only %d kinds: %v", len(kinds), kinds)
	}
	var listed bytes.Buffer
	cmd := newConfigKindsCommand()
	cmd.SetOut(&listed)
	cmd.SetErr(&listed)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	v, err := platformiac.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kinds {
		if !strings.Contains(listed.String(), k) {
			t.Errorf("config kinds does not list %s", k)
		}
		var schema bytes.Buffer
		sc := newConfigSchemaCommand()
		sc.SetOut(&schema)
		sc.SetArgs([]string{k})
		if err := sc.Execute(); err != nil || !strings.Contains(schema.String(), `"`+k+`"`) {
			t.Errorf("config schema %s: %v", k, err)
		}
		for _, ex := range configschemas.Examples(k) {
			raw, err := configschemas.Example(k, ex)
			if err != nil {
				t.Errorf("%s/%s: %v", k, ex, err)
				continue
			}
			docs, err := configschemas.Decode(bytes.NewReader(raw))
			if err != nil {
				t.Errorf("%s/%s: %v", k, ex, err)
				continue
			}
			for _, d := range docs {
				if err := v.Validate(d); err != nil {
					t.Errorf("%s/%s: %v", k, ex, err)
				}
			}
		}
	}
}
