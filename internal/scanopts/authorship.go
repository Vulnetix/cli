package scanopts

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/config"
)

// ── BOM authoring identity flags ─────────────────────────────────────────────
//
// Registered family-wide and read in exactly one place, for the same reason the
// deployment labels are: a document emitted by any member of the scan family
// must be able to say who created it and at which stage its data was captured.
// Resolving that per call site is how six emitting paths came to disagree about
// their own tool name and all six to claim the same lifecycle phase.

const (
	// ManufacturerFlag names the organization that created the BOM.
	ManufacturerFlag = "bom-manufacturer"
	// ManufacturerEnv is the environment equivalent, for a runner that sets it
	// once per job rather than per invocation.
	ManufacturerEnv = "VULNETIX_BOM_MANUFACTURER"
	// LifecycleFlag overrides the capture stages the engine would derive.
	LifecycleFlag = "lifecycle"
)

// AddAuthorshipFlags registers the authoring-identity flags on a command.
func AddAuthorshipFlags(flags *pflag.FlagSet) {
	if flags.Lookup(ManufacturerFlag) != nil {
		return
	}
	flags.String(ManufacturerFlag, "",
		"Organization that created the BOM (CycloneDX metadata.manufacturer). Defaults to the repository owner; omitted when none resolves.")
	flags.String(LifecycleFlag, "",
		"Lifecycle stage(s) this BOM's data was captured at, comma-separated: design, pre-build, build, post-build, operations, discovery, decommission. Default is derived from what the scan read.")
}

// ManufacturerSourcesFromCommand gathers every candidate for
// metadata.manufacturer that flags and the environment can supply.
//
// The git fallback is deliberately left unset here and filled in where git
// context is already collected, so resolving the manufacturer never causes the
// repository to be walked a second time.
func ManufacturerSourcesFromCommand(cmd *cobra.Command) cdx.ManufacturerSources {
	src := cdx.ManufacturerSources{
		Env:   os.Getenv(ManufacturerEnv),
		OrgID: os.Getenv("VULNETIX_ORG_ID"),
	}
	if cmd == nil {
		return src
	}
	if f := cmd.Flags().Lookup(ManufacturerFlag); f != nil {
		src.Override, _ = cmd.Flags().GetString(ManufacturerFlag)
	}
	if f := cmd.Flags().Lookup("org-id"); f != nil {
		if v, _ := cmd.Flags().GetString("org-id"); v != "" {
			src.OrgID = v
		}
	}
	// Whichever CI provider is running states the repository owner, which is the
	// most direct available statement of the organization a run belongs to.
	src.CIOwner = config.LoadCIContext("").RepositoryOwner
	return src
}

// LifecycleOverrideFromCommand reads --lifecycle. Nil means "derive from what
// the scan read"; an unknown phase is rejected rather than treated as a custom
// one, because a typo silently becoming a custom lifecycle name is
// indistinguishable downstream from a deliberate one.
func LifecycleOverrideFromCommand(cmd *cobra.Command) ([]cdx.LifecyclePhase, error) {
	if cmd == nil || cmd.Flags().Lookup(LifecycleFlag) == nil {
		return nil, nil
	}
	raw, _ := cmd.Flags().GetString(LifecycleFlag)
	if raw == "" {
		return nil, nil
	}
	phases, err := cdx.ParseLifecyclePhases(raw)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", LifecycleFlag, err)
	}
	return phases, nil
}
