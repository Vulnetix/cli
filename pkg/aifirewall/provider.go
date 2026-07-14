// Package aifirewall wires local AI clients to the Vulnetix AI Firewall gateway
// and reconciles the org's gateway policy.
//
// The gateway is an OpenAI-compatible proxy at
//
//	https://guardrails.vulnetix.com/{providerSlug}/{orgUuid}/v1
//
// The client authenticates as the org with its Vulnetix API key; the org's real
// provider key is held server-side and swapped in by the gateway. So a client is
// "wired" when its base URL points at the gateway AND its API key is the
// Vulnetix key — either half alone is a misconfiguration, and one of them
// (base URL set, key not) silently sends the Vulnetix key to the provider.
package aifirewall

import (
	"fmt"
	"net/url"
	"strings"
)

// DefaultGatewayURL is the hosted gateway.
const DefaultGatewayURL = "https://guardrails.vulnetix.com"

// VulnetixKeyEnv is the environment variable every wired client reads its
// Vulnetix API key from. Its value is referenced by config we write, never
// inlined, so a rc file or a committed settings.json never holds the secret.
const VulnetixKeyEnv = "VULNETIX_API_KEY"

// Wire is a request format the gateway may or may not proxy for a provider.
const (
	WireChat      = "chat"      // OpenAI /v1/chat/completions
	WireResponses = "responses" // OpenAI /v1/responses — what Codex requires
	WireMessages  = "messages"  // Anthropic /v1/messages — what Claude Code speaks
)

// Provider is one upstream the gateway can proxy, plus the local knowledge the
// server does not have: which environment variables real SDKs actually read.
type Provider struct {
	Slug        string
	DisplayName string

	// APIKeyEnv is the variable an SDK reads its credential from. For a wired
	// client this must hold the Vulnetix API key, not the provider's.
	APIKeyEnv string

	// BaseURLEnv lists the variables that SDKs genuinely honour for overriding
	// the API host — verified, not guessed. An empty list means no SDK reads an
	// environment variable for this provider's base URL, so the only way to route
	// it through the gateway is to set base_url in code (see `ai-firewall
	// snippet`). Inventing a plausible-looking variable here would be worse than
	// useless: the user would believe they were protected while their traffic
	// went straight to the provider.
	BaseURLEnv []string

	// Wire is the request format this provider's SDKs speak.
	Wire string

	// Verified records whether the BaseURLEnv list was confirmed against the
	// SDK's source, as opposed to its documentation.
	Verified bool
}

// EnvWired reports whether pointing this provider at the gateway can be done
// with environment variables alone.
func (p Provider) EnvWired() bool { return len(p.BaseURLEnv) > 0 }

var providers = []Provider{
	{
		Slug: "openai", DisplayName: "OpenAI",
		APIKeyEnv: "OPENAI_API_KEY",
		// OPENAI_BASE_URL is read by openai-python >=1.0 and openai-node.
		// OPENAI_API_BASE is the older spelling, and is what langchain-openai and
		// LlamaIndex read — both are written, so those frameworks are covered
		// without any framework-specific config file.
		BaseURLEnv: []string{"OPENAI_BASE_URL", "OPENAI_API_BASE"},
		Wire:       WireChat, Verified: true,
	},
	{
		Slug: "anthropic", DisplayName: "Anthropic",
		// Deliberately not ANTHROPIC_API_KEY: that variable is sent as the
		// `x-api-key` header, and the gateway authenticates with
		// `Authorization: Bearer`. ANTHROPIC_AUTH_TOKEN is the one that produces a
		// Bearer header.
		APIKeyEnv:  "ANTHROPIC_AUTH_TOKEN",
		BaseURLEnv: []string{"ANTHROPIC_BASE_URL"},
		Wire:       WireMessages, Verified: true,
	},
	{
		Slug: "groq", DisplayName: "Groq",
		APIKeyEnv:  "GROQ_API_KEY",
		BaseURLEnv: []string{"GROQ_BASE_URL"},
		Wire:       WireChat, Verified: false,
	},
	// Everything below has no base-URL environment variable that any SDK reads.
	// They are reachable through the gateway only by setting base_url in code.
	{Slug: "mistral", DisplayName: "Mistral", APIKeyEnv: "MISTRAL_API_KEY", Wire: WireChat, Verified: true},
	{Slug: "deepseek", DisplayName: "DeepSeek", APIKeyEnv: "DEEPSEEK_API_KEY", Wire: WireChat, Verified: true},
	{Slug: "xai", DisplayName: "xAI", APIKeyEnv: "XAI_API_KEY", Wire: WireChat, Verified: true},
	{Slug: "openrouter", DisplayName: "OpenRouter", APIKeyEnv: "OPENROUTER_API_KEY", Wire: WireChat, Verified: true},
	{Slug: "together", DisplayName: "Together AI", APIKeyEnv: "TOGETHER_API_KEY", Wire: WireChat, Verified: true},
	{Slug: "fireworks", DisplayName: "Fireworks", APIKeyEnv: "FIREWORKS_API_KEY", Wire: WireChat, Verified: true},
}

// Providers returns the local provider registry.
func Providers() []Provider {
	out := make([]Provider, len(providers))
	copy(out, providers)
	return out
}

// ProviderBySlug looks up a provider by its gateway path segment.
func ProviderBySlug(slug string) (Provider, bool) {
	for _, p := range providers {
		if p.Slug == slug {
			return p, true
		}
	}
	return Provider{}, false
}

// InfoBaseURLEnv is the variable name used to record the gateway URL of a
// provider that no SDK can be pointed at with environment variables. Nothing
// reads it; it exists so `ai-firewall status` can tell "this org uses Mistral
// through the gateway" from "this org has never heard of Mistral", and so the
// value is to hand when you write the base_url into code.
func InfoBaseURLEnv(slug string) string {
	return "VULNETIX_AIFW_" + strings.ToUpper(strings.ReplaceAll(slug, "-", "_")) + "_BASE_URL"
}

// GatewayURL builds the base URL a client points at: the gateway, the provider
// slug, the org, and — for the OpenAI-shaped SDKs — the version segment.
//
// The two SDK families disagree about who owns the "/v1", and getting it wrong
// produces a 404 on a path with "/v1/v1/" in it that is baffling to debug:
//
//   - OpenAI's base_url INCLUDES the version ("https://api.openai.com/v1"); the
//     SDK appends only "/chat/completions" or "/responses".
//   - Anthropic's base_url is the bare ROOT ("https://api.anthropic.com"); the
//     SDK appends "/v1/messages" itself.
//
// So the version segment is appended for every provider except the ones whose
// clients speak the Anthropic wire.
func GatewayURL(gateway, slug, orgUUID string) string {
	base := strings.TrimRight(strings.TrimSpace(gateway), "/")
	if base == "" {
		base = DefaultGatewayURL
	}
	base += "/" + slug + "/" + orgUUID
	if p, ok := ProviderBySlug(slug); ok && p.Wire == WireMessages {
		return base
	}
	return base + "/v1"
}

// GatewayHost is the host part of a gateway URL, used to decide whether a base
// URL found in a client's config points at us or somewhere else.
func GatewayHost(gateway string) (string, error) {
	if strings.TrimSpace(gateway) == "" {
		gateway = DefaultGatewayURL
	}
	u, err := url.Parse(gateway)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", fmt.Errorf("--gateway-url must be an absolute URL, got %q", gateway)
	}
	return u.Hostname(), nil
}
