package cdx

import (
	"fmt"
	"sort"
	"strings"
)

// deployment.go — where a scan's results are deployed, and who owns them.
//
// A repository scan answers "what is in this code". It cannot answer "which of
// our clusters is running the vulnerable version", because a repository has no
// idea where its artefacts end up. That second question is the one an
// organisation with more than a handful of services actually asks, and
// answering it needs two orthogonal labels travelling with every result:
//
//	cluster / namespace / environment — WHERE it is deployed. Low cardinality,
//	  platform-team owned, stable for years.
//	project                           — WHAT it is and who owns it. High
//	  cardinality, dev-team owned, volatile.
//
// They are separate fields rather than one overloaded one because a single scan
// belongs to cluster `prod-eu` AND project `payment-service` simultaneously;
// collapsing them would make either query impossible to answer.
//
// The CLI does not answer fleet-scale questions itself — it holds one
// repository, not a corpus. What it does is attach the labels at the point they
// are actually known (the pipeline that deployed the thing) and carry them into
// the CycloneDX metadata, local memory and the upload envelope, so the server
// can assemble the cross-repository picture.

// Property names for deployment context in CycloneDX metadata.
//
// metadata.properties is the CycloneDX-sanctioned home for namespaced data, so
// a document carrying these stays schema-valid and any other tool can read them.
const (
	PropDeploymentProject     = "vulnetix:deployment/project"
	PropDeploymentCluster     = "vulnetix:deployment/cluster"
	PropDeploymentNamespace   = "vulnetix:deployment/namespace"
	PropDeploymentEnvironment = "vulnetix:deployment/environment"
	// PropDeploymentTagPrefix is the prefix for arbitrary key=value labels.
	PropDeploymentTagPrefix = "vulnetix:deployment/tag/"
)

// DeploymentContext is the set of deployment labels for one run.
//
// Every field is optional, and an unset field stays empty rather than being
// guessed at: a scan that does not know its cluster must not claim one.
type DeploymentContext struct {
	Project     string            `json:"project,omitempty"`
	Cluster     string            `json:"cluster,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// Empty reports whether no deployment context was supplied or inferred.
func (d DeploymentContext) Empty() bool {
	return d.Project == "" && d.Cluster == "" && d.Namespace == "" &&
		d.Environment == "" && len(d.Tags) == 0
}

// String renders the context as a compact one-line label for terminal output.
func (d DeploymentContext) String() string {
	parts := make([]string, 0, 4+len(d.Tags))
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	add("project", d.Project)
	add("cluster", d.Cluster)
	add("namespace", d.Namespace)
	add("environment", d.Environment)
	for _, k := range d.sortedTagKeys() {
		add(k, d.Tags[k])
	}
	return strings.Join(parts, " ")
}

// sortedTagKeys returns the tag keys in a stable order.
//
// Stability matters beyond tidiness: an unordered write would make a document
// regenerated with identical labels differ byte-for-byte, and `bom diff` would
// report a change that did not happen.
func (d DeploymentContext) sortedTagKeys() []string {
	keys := make([]string, 0, len(d.Tags))
	for k := range d.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ApplyDeploymentContext stamps deployment labels into a BOM's metadata.
func ApplyDeploymentContext(bom *BOM, d DeploymentContext) {
	if bom == nil || d.Empty() {
		return
	}
	if bom.Metadata == nil {
		bom.Metadata = &Metadata{}
	}
	set := func(name, value string) {
		if value == "" {
			return
		}
		bom.Metadata.SetProperty(name, value)
	}

	set(PropDeploymentProject, d.Project)
	set(PropDeploymentCluster, d.Cluster)
	set(PropDeploymentNamespace, d.Namespace)
	set(PropDeploymentEnvironment, d.Environment)
	for _, k := range d.sortedTagKeys() {
		set(PropDeploymentTagPrefix+k, d.Tags[k])
	}
}

// DeploymentContextFromBOM reads deployment labels back out of a document.
//
// The inverse of ApplyDeploymentContext, so a document that has been through
// this CLI can be re-tagged or grouped without the caller re-supplying flags.
func DeploymentContextFromBOM(bom *BOM) DeploymentContext {
	var d DeploymentContext
	if bom == nil || bom.Metadata == nil {
		return d
	}
	for _, p := range bom.Metadata.Properties {
		switch p.Name {
		case PropDeploymentProject:
			d.Project = p.Value
		case PropDeploymentCluster:
			d.Cluster = p.Value
		case PropDeploymentNamespace:
			d.Namespace = p.Value
		case PropDeploymentEnvironment:
			d.Environment = p.Value
		default:
			if key, ok := strings.CutPrefix(p.Name, PropDeploymentTagPrefix); ok && key != "" {
				if d.Tags == nil {
					d.Tags = map[string]string{}
				}
				d.Tags[key] = p.Value
			}
		}
	}
	return d
}
