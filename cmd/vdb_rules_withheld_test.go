package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Below Pro the VDB returns every Snort/YARA rule's metadata with the rule text
// null. `--format rules` then has nothing to write, and must say why on stderr
// rather than leave an empty rules file with no explanation.
func TestRulesFormatNotesWithheldText(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		emit     func(*cobra.Command, map[string]interface{}, string, string) error
		wantOut  string
		wantNote bool
	}{
		{"snort withheld", `{"rules":[{"snortId":"1","msg":"m","rawText":null},{"snortId":"2","msg":"n","rawText":null}]}`, emitRulesResponse, "", true},
		{"snort pro", `{"rules":[{"snortId":"1","rawText":"alert tcp any any -> any any (sid:1;)"}]}`, emitRulesResponse, "alert tcp any any -> any any (sid:1;)\n", false},
		{"yara withheld", `{"rules":[{"ruleName":"r","rawText":null}]}`, emitYaraResponse, "", true},
		{"yara pro", `{"rules":[{"ruleName":"r","rawText":"rule r { condition: true }"}]}`, emitYaraResponse, "rule r { condition: true }\n\n", false},
	}
	for _, c := range cases {
		var resp map[string]interface{}
		if err := json.Unmarshal([]byte(c.body), &resp); err != nil {
			t.Fatal(err)
		}
		var out, errOut bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		if err := c.emit(cmd, resp, "rules", ""); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if out.String() != c.wantOut && !(c.wantOut == "" && strings.TrimSpace(out.String()) == "") {
			t.Errorf("%s: stdout = %q, want %q", c.name, out.String(), c.wantOut)
		}
		gotNote := strings.Contains(errOut.String(), "Pro plan")
		if gotNote != c.wantNote {
			t.Errorf("%s: stderr = %q, want note %v", c.name, errOut.String(), c.wantNote)
		}
	}
}
