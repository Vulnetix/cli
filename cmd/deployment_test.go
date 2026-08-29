package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/scanopts"
)

func newDeploymentTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	scanopts.AddDeploymentFlags(c.Flags())
	return c
}

func TestDeploymentFromFlags(t *testing.T) {
	// Clear the inferred sources so the test observes flags alone.
	for _, k := range []string{
		"VULNETIX_ENVIRONMENT", "CI_ENVIRONMENT_NAME", "ENVIRONMENT_NAME",
		"VULNETIX_CLUSTER", "CLUSTER_NAME", "KUBERNETES_CLUSTER_NAME",
		"VULNETIX_NAMESPACE", "POD_NAMESPACE", "KUBERNETES_NAMESPACE",
		"VULNETIX_PROJECT", "CI_PROJECT_NAME",
	} {
		t.Setenv(k, "")
	}

	c := newDeploymentTestCmd()
	if err := c.ParseFlags([]string{
		"--project", "payment-service",
		"--cluster", "prod-eu",
		"--namespace", "payments",
		"--environment", "production",
		"--tag", "team=platform",
		"--tag", "cost-centre=CC-1024",
	}); err != nil {
		t.Fatal(err)
	}

	d := scanopts.DeploymentFromCommand(c)
	if d.Project != "payment-service" || d.Cluster != "prod-eu" ||
		d.Namespace != "payments" || d.Environment != "production" {
		t.Fatalf("deployment = %+v", d)
	}
	if d.Tags["team"] != "platform" || d.Tags["cost-centre"] != "CC-1024" {
		t.Errorf("tags = %v", d.Tags)
	}
}

// TestDeploymentInfersFromEnvironment covers the pipeline that exports the
// labels once for a whole job rather than passing flags to each command.
func TestDeploymentInfersFromEnvironment(t *testing.T) {
	t.Setenv("VULNETIX_CLUSTER", "staging-us")
	t.Setenv("POD_NAMESPACE", "checkout")

	c := newDeploymentTestCmd()
	if err := c.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	d := scanopts.DeploymentFromCommand(c)
	if d.Cluster != "staging-us" {
		t.Errorf("Cluster = %q, want staging-us", d.Cluster)
	}
	if d.Namespace != "checkout" {
		t.Errorf("Namespace = %q, want checkout", d.Namespace)
	}
}

// TestDeploymentFlagBeatsEnvironment pins precedence: an explicit flag is a
// deliberate statement about this run and must win over ambient environment.
func TestDeploymentFlagBeatsEnvironment(t *testing.T) {
	t.Setenv("VULNETIX_CLUSTER", "staging-us")

	c := newDeploymentTestCmd()
	if err := c.ParseFlags([]string{"--cluster", "prod-eu"}); err != nil {
		t.Fatal(err)
	}
	if got := scanopts.DeploymentFromCommand(c).Cluster; got != "prod-eu" {
		t.Errorf("Cluster = %q, want the flag value prod-eu", got)
	}
}

// TestDeploymentUnsetStaysEmpty is the "null, never zero" rule: a scan that
// does not know its cluster must not claim one.
func TestDeploymentUnsetStaysEmpty(t *testing.T) {
	for _, k := range []string{
		"VULNETIX_ENVIRONMENT", "CI_ENVIRONMENT_NAME", "ENVIRONMENT_NAME",
		"VULNETIX_CLUSTER", "CLUSTER_NAME", "KUBERNETES_CLUSTER_NAME",
		"VULNETIX_NAMESPACE", "POD_NAMESPACE", "KUBERNETES_NAMESPACE",
		"VULNETIX_PROJECT", "CI_PROJECT_NAME",
	} {
		t.Setenv(k, "")
	}
	c := newDeploymentTestCmd()
	if err := c.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if d := scanopts.DeploymentFromCommand(c); !d.Empty() {
		t.Errorf("deployment = %+v, want empty", d)
	}
}

func TestDeploymentRoundTripsThroughBOM(t *testing.T) {
	want := cdx.DeploymentContext{
		Project: "payment-service", Cluster: "prod-eu",
		Namespace: "payments", Environment: "production",
		Tags: map[string]string{"team": "platform"},
	}
	bom := &cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: "1.7", Version: 1}
	cdx.ApplyDeploymentContext(bom, want)

	got := cdx.DeploymentContextFromBOM(bom)
	if got.Project != want.Project || got.Cluster != want.Cluster ||
		got.Namespace != want.Namespace || got.Environment != want.Environment {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if got.Tags["team"] != "platform" {
		t.Errorf("tags = %v", got.Tags)
	}

	// Re-applying must overwrite in place, not append a duplicate property —
	// two values for the same cluster would make the document self-contradicting.
	cdx.ApplyDeploymentContext(bom, cdx.DeploymentContext{Cluster: "prod-us"})
	count := 0
	for _, p := range bom.Metadata.Properties {
		if p.Name == cdx.PropDeploymentCluster {
			count++
			if p.Value != "prod-us" {
				t.Errorf("cluster = %q, want the re-applied prod-us", p.Value)
			}
		}
	}
	if count != 1 {
		t.Errorf("cluster property appears %d times, want 1", count)
	}
}

// TestStampDeploymentJSONPreservesUnknownFields pins that labelling a
// serialised document does not narrow it. The bytes come from the shared
// vdb-cyclonedx builder, which emits fields the internal model does not
// declare; decoding through that model would silently drop them.
func TestStampDeploymentJSONPreservesUnknownFields(t *testing.T) {
	input := []byte(`{
	  "bomFormat":"CycloneDX","specVersion":"1.7","version":1,
	  "metadata":{"timestamp":"2026-08-01T00:00:00Z","lifecycles":[{"phase":"build"}]},
	  "annotations":[{"bom-ref":"a","text":"kept"}],
	  "components":[{"type":"library","name":"x","evidence":{"identity":{"confidence":0.9}}}]
	}`)

	out, err := scanopts.StampDeploymentJSON(input, cdx.DeploymentContext{Cluster: "prod-eu"})
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{"annotations", "evidence", "lifecycles", "prod-eu"} {
		if !strings.Contains(string(out), must) {
			t.Errorf("stamped document lost %q", must)
		}
	}
}
