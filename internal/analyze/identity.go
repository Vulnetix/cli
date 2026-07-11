package analyze

// Identity resolution and bot classification.
//
// Everything downstream depends on this. If the same human counts as four contributors, the
// bus factor is wrong, the contributor count is wrong, and the ownership concentration is
// wrong — and they are wrong in the reassuring direction, which is worse. If a CI bot counts
// as a contributor, the same.
//
// Two decisions here differ from the prior art, deliberately.
//
// First, AI coding agents get their own bot kind. DevStats folds `copilot`, `claude` and
// `codex` into the same denylist as Jenkins, which answers "is this a human" but throws away
// "was this written by an agent" — and that second question is one our users are actually
// asking now. So `ai-agent` is a distinct classification, excluded from human contributor
// counts but countable on its own.
//
// Second, every merge is recorded with the rule that made it. git-intelligence merges
// identities by Levenshtein similarity ≥ 0.85 and reports the result as fact. Merging is a
// judgement and it is sometimes wrong; a judgement in an evidence-backed report has to show
// its working, so each alias carries the rule and a confidence.

import (
	"regexp"
	"strings"
)

// exactBotEmails are forge system addresses — no human is behind any of them.
var exactBotEmails = map[string]bool{
	"noreply@github.com": true,
	"actions@github.com": true,
	"41898282+github-actions[bot]@users.noreply.github.com": true,
	"support@github.com": true,
	"noreply@gitlab.com": true,
}

// namedBots are the CI and dependency bots that show up in nearly every repository.
var namedBots = map[string]string{
	"dependabot":       "dependency-bot",
	"renovate":         "dependency-bot",
	"renovatebot":      "dependency-bot",
	"greenkeeper":      "dependency-bot",
	"snyk-bot":         "dependency-bot",
	"whitesource-bolt": "dependency-bot",
	"pyup-bot":         "dependency-bot",
	"github-actions":   "ci",
	"actions-user":     "ci",
	"jenkins":          "ci",
	"travis":           "ci",
	"circleci":         "ci",
	"gitlab-ci":        "ci",
	"azure-devops":     "ci",
	"codecov":          "ci",
	"sonarcloud":       "ci",
	"codacy":           "ci",
	"deepsource":       "ci",
	"semantic-release": "ci",
}

// aiAgents are coding agents. They are bots, but they are not CI: a commit authored by an
// agent is a different fact from a commit made by a build server, and collapsing the two
// throws away the more interesting one.
var aiAgents = map[string]bool{
	"copilot":       true,
	"claude":        true,
	"codex":         true,
	"devin":         true,
	"jules":         true,
	"cursor":        true,
	"aider":         true,
	"sweep-ai":      true,
	"codegen":       true,
	"claude-code":   true,
	"openai-codex":  true,
	"google-jules":  true,
	"gemini-cli":    true,
	"amp":           true,
	"factory-droid": true,
}

// genericBotWords catch the long tail of service accounts. Deliberately conservative: a
// person legitimately called "Robert Deploy" should not be reclassified as a robot, so these
// only match when the whole username is bot-shaped, not when the word merely appears.
var genericBotWords = []string{
	"automation", "deploy-bot", "buildbot", "service-account", "robot", "pipeline-bot",
}

var personalDomains = map[string]bool{
	"gmail.com": true, "yahoo.com": true, "hotmail.com": true, "outlook.com": true,
	"icloud.com": true, "me.com": true, "live.com": true, "msn.com": true,
	"aol.com": true, "protonmail.com": true, "proton.me": true, "fastmail.com": true,
}

var (
	numericAccount     = regexp.MustCompile(`^\d+$`)
	githubHandleSuffix = regexp.MustCompile(`^(\d+)\+(.+)$`)
)

// ClassifyIdentity fills in the bot, email-kind and login fields for one git identity.
//
// The bot cascade is ordered most-specific-first and the rule that fired is recorded, so a
// user who disagrees with a classification can see exactly what made it and fix the catalog
// rather than guess.
func ClassifyIdentity(name, email string) Identity {
	id := Identity{Name: strings.TrimSpace(name), Email: strings.ToLower(strings.TrimSpace(email))}

	user, domain := splitEmail(id.Email)

	// GitHub's noreply form carries the login: 12345+octocat@users.noreply.github.com
	if m := githubHandleSuffix.FindStringSubmatch(user); m != nil && strings.Contains(domain, "github.com") {
		id.Login = m[2]
		user = m[2]
	}

	base := strings.TrimSuffix(strings.TrimSuffix(user, "[bot]"), "-bot")

	switch {
	case exactBotEmails[id.Email]:
		id.IsBot, id.BotKind, id.BotRule = true, "forge", "exact-bot-email"

	case aiAgents[base] || aiAgents[user] || strings.HasSuffix(user, "[bot]") && aiAgents[base]:
		// An agent's commits are neither a human's nor a build server's. Counting them as
		// either distorts every contributor metric in a different direction.
		id.IsBot, id.BotKind, id.BotRule = true, "ai-agent", "ai-agent-login"

	case namedBots[base] != "":
		id.IsBot, id.BotKind, id.BotRule = true, namedBots[base], "named-bot-login"

	case strings.HasSuffix(user, "[bot]"):
		id.IsBot, id.BotKind, id.BotRule = true, "generic", "bot-suffix"

	case numericAccount.MatchString(user):
		// A username that is only digits is a machine account; a person's address is not "12345@".
		id.IsBot, id.BotKind, id.BotRule = true, "numeric-account", "numeric-username"

	default:
		for _, w := range genericBotWords {
			if base == w {
				id.IsBot, id.BotKind, id.BotRule = true, "generic", "generic-bot-word"

				break
			}
		}
	}

	if !id.IsBot {
		id.BotKind = "none"
	}

	id.EmailKind = classifyDomain(user, domain)

	return id
}

func classifyDomain(user, domain string) string {
	switch {
	case domain == "":
		return "unknown"
	case strings.Contains(user, "noreply") || strings.Contains(domain, "noreply"):
		return "noreply"
	case strings.Contains(domain, "github.com") || strings.Contains(domain, "gitlab.com"):
		return "forge"
	case personalDomains[domain]:
		return "personal"
	case strings.HasSuffix(domain, ".edu") || strings.HasSuffix(domain, ".ac.uk"):
		return "academic"
	case strings.HasSuffix(domain, ".gov"):
		return "government"
	case strings.HasSuffix(domain, ".org"):
		return "organization"
	default:
		return "corporate"
	}
}

func splitEmail(email string) (user, domain string) {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return email, ""
	}

	return email[:at], email[at+1:]
}

// IdentitySet accumulates identities and merges the ones that are the same person.
//
// Merging is by normalised email only. That is a deliberately conservative choice: name
// similarity (git-intelligence merges at Levenshtein ≥ 0.85) merges "Chris Langton" with
// "Chris Langtry", and a wrong merge is invisible in the output while a missed merge is
// merely a duplicate row someone can see. Where two identities share a GitHub login parsed
// out of a noreply address, they are merged on that instead — that one is a fact, not a guess.
type IdentitySet struct {
	byKey map[string]*ContributorRecord
	order []string
}

func NewIdentitySet() *IdentitySet {
	return &IdentitySet{byKey: map[string]*ContributorRecord{}}
}

// key is the login when we have one (authoritative), else the email.
func identityKey(id Identity) string {
	if id.Login != "" {
		return "login:" + strings.ToLower(id.Login)
	}

	return "email:" + id.Email
}

// Observe records one appearance of an identity and returns the contributor it belongs to.
func (s *IdentitySet) Observe(id Identity) *ContributorRecord {
	k := identityKey(id)
	c, ok := s.byKey[k]
	if !ok {
		c = &ContributorRecord{
			ID:       "contributor-" + safeID(k),
			Type:     "contributor",
			Identity: &id,
		}
		s.byKey[k] = c
		s.order = append(s.order, k)

		return c
	}

	// Same person, different spelling of their name or address. Record it as an alias with the
	// rule that merged it, so the judgement is auditable rather than assumed.
	if c.Identity.Email != id.Email || c.Identity.Name != id.Name {
		already := false
		for _, a := range c.Aliases {
			if a.Identity.Email == id.Email && a.Identity.Name == id.Name {
				already = true

				break
			}
		}
		if !already {
			rule := "normalized-email"
			if id.Login != "" {
				rule = "github-handle"
			}
			c.Aliases = append(c.Aliases, Alias{Identity: id, MergedBy: rule, Confidence: 1})
		}
	}

	return c
}

// All returns the contributors in first-seen order — deterministic output for the same input.
func (s *IdentitySet) All() []*ContributorRecord {
	out := make([]*ContributorRecord, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.byKey[k])
	}

	return out
}

var unsafeID = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func safeID(s string) string {
	return strings.Trim(unsafeID.ReplaceAllString(s, "-"), "-")
}
