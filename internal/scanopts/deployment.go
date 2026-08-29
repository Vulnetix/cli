package scanopts

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vulnetix/cli/v3/internal/cdx"
)

// ─────────────────────────────────────────────────────────────────────────
// deployment.go — the flag surface for deployment context.
//
// The model, the metadata property names and the BOM stamping live in
// internal/cdx/deployment.go, because they are facts about a CycloneDX
// document rather than facts about a command line, and internal/pipeline needs
// them without importing this package. What lives here is only the translation
// from flags and environment into that model — this package already owns
// "flags become options", so it is where a second, drifting translation is
// least likely to appear.
// ─────────────────────────────────────────────────────────────────────────

// DeploymentContext is the deployment label set. Aliased from internal/cdx so
// call sites read naturally without a second type to keep in step.
type DeploymentContext = cdx.DeploymentContext

// AddDeploymentFlags registers the deployment-context flags on a flag set.
//
// Registered on the whole scan family via addScanFlags, plus cdx, bom import
// and upload. AGENTS.md requires a family-wide flag to be honoured family-wide,
// and these are read in exactly one place — deploymentContextFromFlags — so no
// subcommand can quietly ignore them.
func AddDeploymentFlags(f *pflag.FlagSet) {
	// addScanFlags runs once per family member and `scan` also composes other
	// flag helpers, so guard against double registration.
	if f.Lookup("project") != nil {
		return
	}
	f.String("project", "", "Project this scan belongs to (what it is / who owns it)")
	f.String("cluster", "", "Cluster this artefact is deployed to (where it runs)")
	f.String("namespace", "", "Namespace within the cluster")
	f.String("environment", "", "Deployment environment, e.g. production, staging")
	f.StringArray("tag", nil, "Additional deployment label as key=value (repeatable)")
}

// DeploymentFromCommand reads the deployment flags, falling back to CI.
func DeploymentFromCommand(cmd *cobra.Command) DeploymentContext {
	get := func(name string) string {
		if cmd.Flags().Lookup(name) == nil {
			return ""
		}
		v, _ := cmd.Flags().GetString(name)
		return strings.TrimSpace(v)
	}

	d := DeploymentContext{
		Project:     get("project"),
		Cluster:     get("cluster"),
		Namespace:   get("namespace"),
		Environment: get("environment"),
	}
	if cmd.Flags().Lookup("tag") != nil {
		raw, _ := cmd.Flags().GetStringArray("tag")
		d.Tags = parseDeploymentTags(raw)
	}

	inferred := inferDeploymentContext()
	if d.Project == "" {
		d.Project = inferred.Project
	}
	if d.Cluster == "" {
		d.Cluster = inferred.Cluster
	}
	if d.Namespace == "" {
		d.Namespace = inferred.Namespace
	}
	if d.Environment == "" {
		d.Environment = inferred.Environment
	}
	return d
}

// parseDeploymentTags parses repeatable key=value flags.
//
// Only the first '=' splits, because label values legitimately contain them. A
// pair with no '=' is dropped rather than stored under an empty key — a
// malformed label is worse than no label.
func parseDeploymentTags(raw []string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for _, kv := range raw {
		key, value, found := strings.Cut(kv, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// inferDeploymentContext derives deployment labels from the environment.
//
// Only labels the platform states outright are taken: GitLab exposes a
// first-class deployment environment, Kubernetes projects its namespace through
// the downward API when a workload asks for it, and the VULNETIX_* forms exist
// so a pipeline can set them once for every command in a job.
//
// Nothing is guessed from a branch name. "main means production" is a
// convention this CLI has no business assuming on a user's behalf, and a wrong
// environment label is worse than an absent one — it would attribute a finding
// to a cluster that never ran the code.
func inferDeploymentContext() DeploymentContext {
	return DeploymentContext{
		Environment: firstEnv("VULNETIX_ENVIRONMENT", "CI_ENVIRONMENT_NAME", "ENVIRONMENT_NAME"),
		Cluster:     firstEnv("VULNETIX_CLUSTER", "CLUSTER_NAME", "KUBERNETES_CLUSTER_NAME"),
		Namespace:   firstEnv("VULNETIX_NAMESPACE", "POD_NAMESPACE", "KUBERNETES_NAMESPACE"),
		Project:     firstEnv("VULNETIX_PROJECT", "CI_PROJECT_NAME"),
	}
}

// firstEnv returns the first non-empty environment variable from the list.
func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// StampDeploymentJSON applies deployment labels to already-serialised CycloneDX.
//
// The document arrives as bytes from the shared vdb-cyclonedx builder, so it is
// round-tripped through a generic map rather than the internal model: decoding
// into cdx.BOM and re-encoding would silently drop every field the internal
// model does not declare, and this function has no business narrowing a
// document it was only asked to label.
func StampDeploymentJSON(data []byte, d DeploymentContext) ([]byte, error) {
	if d.Empty() {
		return data, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		doc["metadata"] = meta
	}
	props, _ := meta["properties"].([]any)

	set := func(name, value string) {
		if value == "" {
			return
		}
		for _, raw := range props {
			if p, ok := raw.(map[string]any); ok && p["name"] == name {
				p["value"] = value
				return
			}
		}
		props = append(props, map[string]any{"name": name, "value": value})
	}

	set(cdx.PropDeploymentProject, d.Project)
	set(cdx.PropDeploymentCluster, d.Cluster)
	set(cdx.PropDeploymentNamespace, d.Namespace)
	set(cdx.PropDeploymentEnvironment, d.Environment)

	keys := make([]string, 0, len(d.Tags))
	for k := range d.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		set(cdx.PropDeploymentTagPrefix+k, d.Tags[k])
	}

	meta["properties"] = props
	return json.MarshalIndent(doc, "", "  ")
}
