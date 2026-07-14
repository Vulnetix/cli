package aifirewall

import (
	"strings"
	"testing"
)

func TestEverySnippetWiresTheGatewayAndLeaksNoSecret(t *testing.T) {
	data := SnippetData{
		GatewayURL: GatewayURL(DefaultGatewayURL, "openai", testOrg),
		Provider:   "openai",
		OrgUUID:    testOrg,
		Model:      "gpt-4o",
		KeyEnv:     VulnetixKeyEnv,
	}

	for _, s := range Snippets() {
		t.Run(s.Lang+"-"+s.SDK, func(t *testing.T) {
			body, err := RenderSnippet(s, data)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(body, data.GatewayURL) {
				t.Errorf("the snippet does not point at the gateway:\n%s", body)
			}
			if !strings.Contains(body, VulnetixKeyEnv) {
				t.Errorf("the snippet does not read the key from $%s:\n%s", VulnetixKeyEnv, body)
			}
			if !strings.Contains(body, data.Model) {
				t.Errorf("the snippet does not use the model:\n%s", body)
			}
			// A snippet is printed to a terminal and pasted into a repo. It must
			// carry a variable reference, never a credential.
			if strings.Contains(body, testKey) {
				t.Errorf("the snippet inlined a credential:\n%s", body)
			}
			if strings.Contains(body, "{{") {
				t.Errorf("unrendered template directive left in the output:\n%s", body)
			}
		})
	}
}

// The Vercel AI SDK ignores OPENAI_BASE_URL, so this snippet is not a
// convenience — it is the only way to route it through the firewall. It must set
// baseURL in code and say why.
func TestVercelSnippetSetsBaseURLInCode(t *testing.T) {
	s, err := FindSnippet("ts", "vercel-ai")
	if err != nil {
		t.Fatal(err)
	}
	body, err := RenderSnippet(s, SnippetData{
		GatewayURL: "https://guardrails.vulnetix.com/openai/org/v1",
		Model:      "gpt-4o", KeyEnv: VulnetixKeyEnv, Provider: "openai",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "createOpenAI({") {
		t.Errorf("must use createOpenAI, since the SDK reads no base-URL env var:\n%s", body)
	}
	if !strings.Contains(body, "does NOT read OPENAI_BASE_URL") {
		t.Errorf("the snippet should explain why the env vars do not cover this:\n%s", body)
	}
}

func TestAnthropicSnippetsUseAuthTokenNotAPIKey(t *testing.T) {
	for _, sdk := range []string{"anthropic"} {
		for _, lang := range []string{"python", "ts"} {
			s, err := FindSnippet(lang, sdk)
			if err != nil {
				t.Fatal(err)
			}
			body, err := RenderSnippet(s, SnippetData{
				GatewayURL: "https://guardrails.vulnetix.com/anthropic/org/v1",
				Model:      "claude-sonnet-4-5", KeyEnv: VulnetixKeyEnv, Provider: "anthropic",
			})
			if err != nil {
				t.Fatal(err)
			}
			// api_key would be sent as x-api-key, which the gateway does not accept.
			// Check the code, not the comment that explains this.
			for _, line := range strings.Split(body, "\n") {
				code, _, _ := strings.Cut(line, "//")
				code, _, _ = strings.Cut(code, "#")
				if strings.Contains(code, "api_key=") || strings.Contains(code, "apiKey:") {
					t.Errorf("%s/%s passes api_key; the gateway needs a Bearer token, so it must be auth_token: %q", lang, sdk, line)
				}
			}
			if !strings.Contains(body, "auth_token") && !strings.Contains(body, "authToken") {
				t.Errorf("%s/%s should pass the key as an auth token:\n%s", lang, sdk, body)
			}
		}
	}
}

func TestFindSnippetListsValidPairsOnMiss(t *testing.T) {
	_, err := FindSnippet("cobol", "openai")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "python/openai") {
		t.Errorf("the error should list the valid pairs: %v", err)
	}
}
