package cmd

import (
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/scanopts"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ─────────────────────────────────────────────────────────────────────────
// deployment.go — carrying deployment labels into the upload envelope.
//
// The model and the BOM stamping live in internal/cdx/deployment.go; the flag
// and environment translation lives in internal/scanopts/deployment.go. What is
// left here is the last mile: getting the labels onto every `cli.*` submission.
//
// That last mile needs a package-level value rather than a parameter. CliEnv is
// assembled in two builders (envForCliWithGit and buildCliEnv) reached from a
// dozen submission paths, none of which carry the scan's options struct;
// threading a parameter through all of them to reach two assignments would
// obscure the change rather than clarify it. This is the same reasoning that
// makes `orgEOLBuckets` and `lastContainerSnapshotUuid` package vars, and it is
// set in exactly one place — the root PersistentPreRun — so there is no
// ordering question about when it becomes valid.
// ─────────────────────────────────────────────────────────────────────────

// activeDeployment holds the deployment labels for the current invocation.
//
// Zero-valued (and therefore omitted from every envelope) until
// captureDeploymentContext runs, and zero-valued for a run that supplied none.
// An unlabelled scan must not claim a cluster.
var activeDeployment scanopts.DeploymentContext

// captureDeploymentContext records the run's deployment labels.
//
// Called from the root PersistentPreRun so it applies to every command, not
// only the scan family. Commands that do not register the flags still pick up
// the VULNETIX_* / CI environment forms, which is correct: a pipeline that
// exports VULNETIX_CLUSTER once should have every command in the job labelled.
func captureDeploymentContext(cmd *cobra.Command) {
	activeDeployment = scanopts.DeploymentFromCommand(cmd)
}

// deploymentEnv renders the active labels for a submission envelope, or nil.
func deploymentEnv() *vdb.CliDeploymentContext {
	if activeDeployment.Empty() {
		return nil
	}
	return &vdb.CliDeploymentContext{
		Project:     activeDeployment.Project,
		Cluster:     activeDeployment.Cluster,
		Namespace:   activeDeployment.Namespace,
		Environment: activeDeployment.Environment,
		Tags:        activeDeployment.Tags,
	}
}
