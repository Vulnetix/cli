package cmd

import (
	"strings"
	"testing"

	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
)

// A provider drops out of the wiring targets for opposite reasons — no stored
// key, or an explicit deny — and the remedies are opposites too. Reporting both
// as "no key stored" sent the reader to `key set` for a key already on file.
func TestWhyNotTargetedDistinguishesMissingKeyFromDeny(t *testing.T) {
	pol := aifw.Policy{
		ProviderHasKey: map[string]bool{"openai": true, "groq": false, "anthropic": true},
		ProviderAction: map[string]string{"openai": "deny", "groq": "", "anthropic": "allow"},
	}
	cases := []struct{ slug, want string }{
		{"openai", "denied by org policy"},
		{"groq", "no key stored"},
		{"mistral", "not in the gateway catalog"},
		{"anthropic", "not selected by --provider"},
	}
	for _, c := range cases {
		if got := whyNotTargeted(pol, c.slug); !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to mention %q", c.slug, got, c.want)
		}
	}
}
