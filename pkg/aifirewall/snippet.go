package aifirewall

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var snippetTemplates embed.FS

// Snippet is one language/SDK pair we can emit boilerplate for.
type Snippet struct {
	Lang string
	SDK  string
	File string
	// Provider pins the snippet to one provider when the SDK only speaks to it.
	Provider string
	// Wire is the request format the SDK in this snippet speaks. A snippet cannot
	// be rendered for a provider that does not serve it — an OpenAI-shaped call
	// against Anthropic would be built from the wrong base URL and 404.
	Wire string
	// Note explains why this snippet exists, when the reason is not obvious.
	Note string
}

// Supports reports whether this snippet can be rendered for a provider.
func (s Snippet) Supports(p Provider) bool {
	if s.Provider != "" {
		return s.Provider == p.Slug
	}
	return s.Wire == "" || s.Wire == p.Wire
}

var snippets = []Snippet{
	{Lang: "python", SDK: "openai", File: "python-openai.tmpl", Wire: WireChat},
	{Lang: "python", SDK: "anthropic", File: "python-anthropic.tmpl", Provider: "anthropic"},
	{Lang: "python", SDK: "langchain", File: "python-langchain.tmpl", Wire: WireChat},
	{Lang: "python", SDK: "llamaindex", File: "python-llamaindex.tmpl", Wire: WireChat},
	{Lang: "ts", SDK: "openai", File: "ts-openai.tmpl", Wire: WireChat},
	{Lang: "ts", SDK: "anthropic", File: "ts-anthropic.tmpl", Provider: "anthropic"},
	{
		Lang: "ts", SDK: "vercel-ai", File: "ts-vercel-ai.tmpl", Wire: WireChat,
		Note: "the Vercel AI SDK does not read OPENAI_BASE_URL, so the gateway must be set in code",
	},
	{Lang: "go", SDK: "openai", File: "go-openai.tmpl", Wire: WireChat},
	{Lang: "sh", SDK: "curl", File: "sh-curl.tmpl", Wire: WireChat},
}

// SnippetData is what a template renders against.
type SnippetData struct {
	GatewayURL string
	Provider   string
	OrgUUID    string
	Model      string
	KeyEnv     string
}

// Snippets returns the registry.
func Snippets() []Snippet {
	out := make([]Snippet, len(snippets))
	copy(out, snippets)
	return out
}

// SnippetLangs / SnippetSDKs power shell completion and the error message on a
// bad pair, from the one registry.
func SnippetLangs() []string { return uniqueSorted(func(s Snippet) string { return s.Lang }) }
func SnippetSDKs() []string  { return uniqueSorted(func(s Snippet) string { return s.SDK }) }

func uniqueSorted(get func(Snippet) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range snippets {
		v := get(s)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// FindSnippet resolves a lang/SDK pair.
func FindSnippet(lang, sdk string) (Snippet, error) {
	for _, s := range snippets {
		if s.Lang == lang && s.SDK == sdk {
			return s, nil
		}
	}
	var pairs []string
	for _, s := range snippets {
		pairs = append(pairs, s.Lang+"/"+s.SDK)
	}
	sort.Strings(pairs)
	return Snippet{}, fmt.Errorf("no snippet for --lang %s --sdk %s (available: %s)", lang, sdk, strings.Join(pairs, ", "))
}

// RenderSnippet produces ready-to-run boilerplate wired to the gateway.
func RenderSnippet(s Snippet, data SnippetData) (string, error) {
	body, err := snippetTemplates.ReadFile("templates/" + s.File)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New(s.File).Parse(string(body))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
