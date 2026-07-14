package aifirewall

import (
	"fmt"
	"regexp"
	"strings"
)

// Severity of a check finding.
type Severity string

const (
	SeverityError Severity = "error" // requests will fail, or policy is not enforced
	SeverityWarn  Severity = "warn"
)

// Check is one finding about the local setup versus the org's policy.
type Check struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Client   string   `json:"client,omitempty"`
	Message  string   `json:"message"`
}

// Policy is the org's gateway policy, in the shape the checks need.
type Policy struct {
	// ProviderAction maps a provider slug to "allow", "deny", or "" (default).
	ProviderAction map[string]string
	// ProviderHasKey maps a provider slug to whether a BYOK key is stored.
	ProviderHasKey map[string]bool
	// ModelAction maps "provider/model" to "allow" or "deny".
	ModelAction map[string]string
	// AllowlistMode holds the providers with at least one allow entry. For those,
	// a model that is not on the list is refused — the single most surprising
	// semantic in the product, and the reason a "not denied" model can still fail.
	AllowlistMode map[string]bool
	Guardrails    []Guardrail
	Gateway       *Gateway
}

// Guardrail is one rule, in the shape the checks need.
type Guardrail struct {
	Name     string
	RuleType string
	Pattern  string
	Enabled  bool
	Priority int
}

// ModelAllowed reports whether a model would pass policy for a provider, and why
// not if it would not. The empty model is "no opinion".
func (p Policy) ModelAllowed(provider, model string) (bool, string) {
	if model == "" {
		return true, ""
	}
	model = strings.TrimPrefix(model, provider+"/")
	key := provider + "/" + model
	switch p.ModelAction[key] {
	case "deny":
		return false, "model_denied"
	case "allow":
		return true, ""
	}
	if p.AllowlistMode[provider] {
		return false, "model_not_allowed"
	}
	return true, ""
}

// RunChecks compares what is configured locally against what the gateway will
// enforce, and reports every way a request is going to fail — or silently not be
// screened at all.
func RunChecks(pol Policy, detected []Detected, gatewayHost string) []Check {
	var checks []Check

	for _, d := range detected {
		if d.State == StateAbsent {
			continue
		}
		provider := clientProvider(d.Client)

		if d.State == StateElsewhere {
			checks = append(checks, Check{
				ID: "bypasses_firewall", Severity: SeverityWarn, Client: d.Client.ID,
				Message: fmt.Sprintf("base URL is %s, not the gateway — requests from %s are not screened by the AI Firewall", d.BaseURL, d.Client.DisplayName),
			})
			continue
		}
		if d.State != StateWired {
			continue
		}

		// From here the client is pointed at us, so the gateway's policy decides
		// whether its requests survive. Each of these is a 403 the user would
		// otherwise meet at runtime with no idea why.
		if provider != "" {
			if pol.ProviderAction[provider] == "deny" {
				checks = append(checks, Check{
					ID: "provider_denied", Severity: SeverityError, Client: d.Client.ID,
					Message: fmt.Sprintf("%s is wired to %s, which this org denies — every request returns 403 provider_denied", d.Client.DisplayName, provider),
				})
			}
			if has, known := pol.ProviderHasKey[provider]; known && !has {
				checks = append(checks, Check{
					ID: "provider_key_missing", Severity: SeverityError, Client: d.Client.ID,
					Message: fmt.Sprintf("no %s key is stored for this org — every request returns 403 provider_key_missing. Run 'vulnetix ai-firewall key set %s'", provider, provider),
				})
			}
			if ok, reason := pol.ModelAllowed(provider, d.Model); !ok {
				detail := "this org denies it"
				if reason == "model_not_allowed" {
					detail = fmt.Sprintf("%s is in allowlist mode and this model is not on the list", provider)
				}
				checks = append(checks, Check{
					ID: reason, Severity: SeverityError, Client: d.Client.ID,
					Message: fmt.Sprintf("%s has %q pinned, but %s — every request returns 403 %s", d.Client.DisplayName, d.Model, detail, reason),
				})
			}
		}

		if ok, why := SupportsWire(pol.Gateway, d.Client, provider); !ok {
			checks = append(checks, Check{
				ID: "wire_unsupported", Severity: SeverityWarn, Client: d.Client.ID,
				Message: why,
			})
		}

		// A base URL pointing at the gateway with the provider's own key still in
		// the environment sends that key to us and fails auth — and worse, a user
		// who set only the base URL believes they are wired when they are not.
		for envKey, set := range d.KeyEnvSet {
			p, ok := providerByKeyEnv(envKey)
			if !ok || !hasBaseURLWired(d, p) {
				continue
			}
			if !set {
				checks = append(checks, Check{
					ID: "key_env_unset", Severity: SeverityWarn, Client: d.Client.ID,
					Message: fmt.Sprintf("%s points at the gateway but $%s is unset — requests will fail to authenticate. Export $%s (or re-run install)", p.DisplayName, envKey, VulnetixKeyEnv),
				})
			}
		}
	}

	// A guardrail whose pattern does not compile is skipped by the gateway. The
	// rule is in the dashboard, it looks enforced, and it is not: a silent hole.
	for _, g := range pol.Guardrails {
		if !g.Enabled || g.RuleType == "max_messages" || g.Pattern == "" {
			continue
		}
		if _, err := regexp.Compile(g.Pattern); err != nil {
			msg := fmt.Sprintf("guardrail %q has a pattern that does not compile (%v) — the gateway skips it, so this rule is NOT being enforced", g.Name, err)
			if strings.Contains(g.Pattern, "(?=") || strings.Contains(g.Pattern, "(?<") {
				msg += ". Go's RE2 has no lookahead or lookbehind; drop it — `orgUuid=\\S+` blocks the same requests as `(?<=orgUuid=)\\S+`"
			}
			checks = append(checks, Check{ID: "guardrail_pattern_invalid", Severity: SeverityWarn, Message: msg})
		}
	}

	return checks
}

// hasBaseURLWired reports whether this client actually points at the gateway for
// p. The shell can be wired for one provider and not another, so it is not
// enough that p *could* be wired by environment variable — a provider nobody has
// wired must not produce a finding about its key.
func hasBaseURLWired(d Detected, p Provider) bool {
	if d.Client.ID != "shell" {
		return clientProvider(d.Client) == p.Slug
	}
	return d.WiredProviders[p.Slug]
}

func providerByKeyEnv(envKey string) (Provider, bool) {
	for _, p := range Providers() {
		if p.APIKeyEnv == envKey {
			return p, true
		}
	}
	return Provider{}, false
}

// clientProvider is the provider a client talks to, when it only talks to one.
func clientProvider(c Client) string {
	if len(c.Providers) == 1 {
		return c.Providers[0]
	}
	return ""
}

// Errors counts the findings that mean requests are failing right now.
func Errors(checks []Check) int {
	n := 0
	for _, c := range checks {
		if c.Severity == SeverityError {
			n++
		}
	}
	return n
}

// Warnings counts the non-fatal findings.
func Warnings(checks []Check) int {
	n := 0
	for _, c := range checks {
		if c.Severity == SeverityWarn {
			n++
		}
	}
	return n
}
