// Package tetragon renders the feeds' block-mode process rules as a Tetragon
// TracingPolicy, so the kernel refuses a matching exec before it runs.
//
// This is the in-kernel counterpart to the seccomp guard, for nodes that run
// Tetragon. It is off unless an operator renders the policy
// (vulnetix-sensor tetragon-policy) and applies it with kubectl. The sensor
// does not apply it.
//
// Only what Tetragon can express is rendered: a Sigma process_creation rule
// whose one selection tests Image alone, with no modifier, startswith or
// endswith. Everything else is listed as skipped with the reason, and keeps
// running in the sensor as detection. The policy refuses with EPERM through
// Tetragon's Override action on security_bprm_creds_for_exec, which needs a
// kernel built with CONFIG_BPF_KPROBE_OVERRIDE. Not yet run against a live
// Tetragon; read the policy before applying it.
package tetragon

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

// PolicyName is the TracingPolicy's name, and how the sensor recognises the
// events it causes.
const PolicyName = "vulnetix-exec-block"

// Hook is the kernel function the policy overrides.
const Hook = "security_bprm_creds_for_exec"

// Tetragon allows a bounded number of values per matchArgs.
const maxValues = 64

// Skipped is a rule that was not rendered, and why.
type Skipped struct {
	RuleUUID string
	Reason   string
}

// Rendered is a policy and what went into it.
type Rendered struct {
	YAML    []byte
	Used    []string
	Skipped []Skipped
}

// Render builds the policy from the rules of verified feeds. A rule must be a
// SIGMA rule in block mode and not disabled; an unverified feed's rules never
// block, here as in the sensor.
func Render(feeds []feed.Loaded) (Rendered, error) {
	var out Rendered
	paths := map[string]map[string]bool{"Equal": {}, "Prefix": {}, "Postfix": {}}
	for _, f := range feeds {
		for _, r := range f.Rules {
			if !strings.EqualFold(r.RuleType, "SIGMA") {
				continue
			}
			switch {
			case !f.Verified:
				out.Skipped = append(out.Skipped, Skipped{r.RuleUUID, "its feed is not verified"})
			case r.Disabled:
				out.Skipped = append(out.Skipped, Skipped{r.RuleUUID, "disabled"})
			case !strings.EqualFold(r.DeployMode, "block"):
				out.Skipped = append(out.Skipped, Skipped{r.RuleUUID, "starts in " + r.DeployMode + " mode, not block"})
			default:
				op, values, reason := imageMatch(r.Body)
				if reason != "" {
					out.Skipped = append(out.Skipped, Skipped{r.RuleUUID, reason})

					continue
				}
				for _, v := range values {
					paths[op][v] = true
				}
				out.Used = append(out.Used, r.RuleUUID)
			}
		}
	}
	if len(out.Used) == 0 {
		return out, fmt.Errorf("no rule can be rendered as a Tetragon policy")
	}

	var selectors []map[string]any
	for _, op := range []string{"Equal", "Prefix", "Postfix"} {
		values := make([]string, 0, len(paths[op]))
		for v := range paths[op] {
			values = append(values, v)
		}
		sort.Strings(values)
		for len(values) > 0 {
			n := min(len(values), maxValues)
			selectors = append(selectors, map[string]any{
				"matchArgs":    []map[string]any{{"index": 0, "operator": op, "values": values[:n]}},
				"matchActions": []map[string]any{{"action": "Override", "argError": -1}},
			})
			values = values[n:]
		}
	}
	if len(selectors) > 5 {
		return out, fmt.Errorf("the rules need %d selectors and Tetragon allows 5; split the feed", len(selectors))
	}
	policy := map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]any{
			"name":   PolicyName,
			"labels": map[string]string{"app.kubernetes.io/managed-by": "vulnetix-sensor"},
		},
		"spec": map[string]any{
			"kprobes": []map[string]any{{
				"call":      Hook,
				"syscall":   false,
				"args":      []map[string]any{{"index": 0, "type": "linux_binprm"}},
				"selectors": selectors,
			}},
		},
	}
	body, err := yaml.Marshal(policy)
	if err != nil {
		return out, err
	}
	header := "# Rendered by vulnetix-sensor tetragon-policy from rules: " + strings.Join(out.Used, ", ") + "\n" +
		"# Refuses a matching exec with EPERM in the kernel, in every sensor mode. Re-render after a\n" +
		"# rule changes or is marked a false positive.\n"
	out.YAML = append([]byte(header), body...)

	return out, nil
}

// imageMatch reads a Sigma rule that tests only Image and returns the Tetragon
// operator and values, or why it cannot be rendered.
func imageMatch(body string) (string, []string, string) {
	var doc struct {
		LogSource struct {
			Category string `yaml:"category"`
		} `yaml:"logsource"`
		Detection map[string]yaml.Node `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		return "", nil, "not valid YAML"
	}
	if doc.LogSource.Category != "process_creation" {
		return "", nil, "not a process_creation rule"
	}
	cond, ok := doc.Detection["condition"]
	if !ok || len(doc.Detection) != 2 {
		return "", nil, "needs exactly one selection and a condition"
	}
	var condition string
	if cond.Decode(&condition) != nil {
		return "", nil, "the condition is not one selection name"
	}
	sel, ok := doc.Detection[strings.TrimSpace(condition)]
	if !ok {
		return "", nil, "the condition is not one selection name"
	}
	var fields map[string]yaml.Node
	if sel.Decode(&fields) != nil || len(fields) != 1 {
		return "", nil, "the selection tests more than Image"
	}
	for key, node := range fields {
		field, modifier, _ := strings.Cut(key, "|")
		if field != "Image" {
			return "", nil, "the selection tests " + field + ", not Image"
		}
		op := map[string]string{"": "Equal", "startswith": "Prefix", "endswith": "Postfix"}[modifier]
		if op == "" {
			return "", nil, "modifier " + modifier + " has no Tetragon operator"
		}
		var values []string
		if node.Kind == yaml.ScalarNode {
			values = []string{node.Value}
		} else if node.Decode(&values) != nil {
			return "", nil, "the Image values are not strings"
		}
		for _, v := range values {
			if v == "" || strings.ContainsAny(v, "*?") {
				return "", nil, "an Image value is empty or has a wildcard"
			}
		}

		return op, values, ""
	}

	return "", nil, "empty selection"
}

// ExactImages returns the exact program paths the given Sigma rules name, for
// the BPF LSM guard, which matches a file by identity and so cannot express a
// prefix or suffix. The caller passes only rules it would block on. A path two
// rules name goes to the first.
func ExactImages(rules []feed.Rule) map[string]feed.Rule {
	out := map[string]feed.Rule{}
	for _, r := range rules {
		if !strings.EqualFold(r.RuleType, "SIGMA") {
			continue
		}
		op, values, reason := imageMatch(r.Body)
		if reason != "" || op != "Equal" {
			continue
		}
		for _, v := range values {
			if _, taken := out[v]; !taken {
				out[v] = r
			}
		}
	}

	return out
}
