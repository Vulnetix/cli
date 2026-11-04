package scanopts

import (
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vulnetix/cli/v4/internal/cdx"
	"github.com/vulnetix/cli/v4/internal/config"
	"github.com/vulnetix/cli/v4/internal/license"
)

// ── BOM authoring identity flags ─────────────────────────────────────────────
//
// Registered family-wide and read in exactly one place, for the same reason the
// deployment labels are: a document emitted by any member of the scan family
// must be able to say who created it and at which stage its data was captured.
// Resolving that per call site is how six emitting paths came to disagree about
// their own tool name and all six to claim the same lifecycle phase.
//
// Every flag has an environment equivalent, for a runner that sets it once per
// job rather than per invocation. A flag beats the environment; both beat an
// overlay file; all three beat what the run derives.

const (
	// ManufacturerFlag names the organization that created the BOM.
	ManufacturerFlag = "bom-manufacturer"
	// ManufacturerEnv is the environment equivalent.
	ManufacturerEnv = "VULNETIX_BOM_MANUFACTURER"
	// LifecycleFlag overrides the capture stages the engine would derive.
	LifecycleFlag = "lifecycle"

	ManufacturerURLFlag  = "bom-manufacturer-url"
	ManufacturerURLEnv   = "VULNETIX_BOM_MANUFACTURER_URL"
	AuthorFlag           = "bom-author"
	AuthorsEnv           = "VULNETIX_BOM_AUTHORS"
	SupplierFlag         = "bom-supplier"
	SupplierEnv          = "VULNETIX_BOM_SUPPLIER"
	SupplierURLFlag      = "bom-supplier-url"
	SupplierURLEnv       = "VULNETIX_BOM_SUPPLIER_URL"
	SerialFlag           = "bom-serial"
	SerialEnv            = "VULNETIX_BOM_SERIAL"
	BOMVersionFlag       = "bom-version"
	BOMVersionEnv        = "VULNETIX_BOM_VERSION"
	LicenseFlag          = "bom-license"
	LicensesEnv          = "VULNETIX_BOM_LICENSES"
	PropertyFlag         = "bom-property"
	PropertiesEnv        = "VULNETIX_BOM_PROPERTIES"
	OverlayFlag          = "bom-overlay"
	OverlayEnv           = "VULNETIX_BOM_OVERLAY"
	ComponentNameFlag    = "component-name"
	ComponentNameEnv     = "VULNETIX_COMPONENT_NAME"
	ComponentVersionFlag = "component-version"
	ComponentVersionEnv  = "VULNETIX_COMPONENT_VERSION"
	ComponentTypeFlag    = "component-type"
	ComponentTypeEnv     = "VULNETIX_COMPONENT_TYPE"
	ComponentGroupFlag   = "component-group"
	ComponentGroupEnv    = "VULNETIX_COMPONENT_GROUP"
	ComponentPurlFlag    = "component-purl"
	ComponentPurlEnv     = "VULNETIX_COMPONENT_PURL"
)

// AuthorshipFlags lists every flag AddAuthorshipFlags registers, for the tests
// that check they are registered and never replayed.
var AuthorshipFlags = []string{
	ManufacturerFlag, ManufacturerURLFlag, AuthorFlag, SupplierFlag, SupplierURLFlag,
	SerialFlag, BOMVersionFlag, LifecycleFlag, LicenseFlag, PropertyFlag, OverlayFlag,
	ComponentNameFlag, ComponentVersionFlag, ComponentTypeFlag, ComponentGroupFlag, ComponentPurlFlag,
}

// AddAuthorshipFlags registers the authoring-identity and customisation flags
// on a command that authors documents. Transformer-tier commands (bom enrich,
// bom import) do not register them: they have no manufacturer to claim.
func AddAuthorshipFlags(flags *pflag.FlagSet) {
	if flags.Lookup(ManufacturerFlag) != nil {
		return
	}
	flags.String(ManufacturerFlag, "",
		"Organisation that created the BOM (metadata.manufacturer.name). Defaults to the repository owner; omitted when none resolves. Env: "+ManufacturerEnv)
	flags.String(ManufacturerURLFlag, "",
		"URL of the manufacturer (metadata.manufacturer.url), replacing the one derived from the git remote. Env: "+ManufacturerURLEnv)
	flags.StringArray(AuthorFlag, nil,
		"Person who authored the document, as 'Name <email>' (metadata.authors, repeatable). Env: "+AuthorsEnv+" (comma- or semicolon-separated)")
	flags.String(SupplierFlag, "",
		"Organisation that supplied the component the BOM describes (metadata.supplier.name). Env: "+SupplierEnv)
	flags.String(SupplierURLFlag, "",
		"URL of the supplier (metadata.supplier.url). Env: "+SupplierURLEnv)
	flags.String(SerialFlag, "",
		"Document serial number (serialNumber): a urn:uuid, a UUID, or any stable string, which becomes a UUIDv5 of itself. Env: "+SerialEnv)
	flags.Int(BOMVersionFlag, 0,
		"Document version (version), 1 or more. Env: "+BOMVersionEnv)
	flags.String(LifecycleFlag, "",
		"Lifecycle stage(s) this BOM's data was captured at, comma-separated: design, pre-build, build, post-build, operations, discovery, decommission. Default is derived from what the scan read.")
	flags.StringArray(LicenseFlag, nil,
		"Licence of the document itself: an SPDX id, an SPDX expression or a name (metadata.licenses, repeatable). Env: "+LicensesEnv)
	flags.StringArray(PropertyFlag, nil,
		"Document property as name=value (metadata.properties, repeatable). Names starting vulnetix: are reserved. Env: "+PropertiesEnv)
	flags.StringArray(OverlayFlag, nil,
		"CycloneDX JSON fragment merged into the document before validation (repeatable; a later file wins). Env: "+OverlayEnv)
	flags.String(ComponentNameFlag, "", "Name of the subject component (metadata.component.name); defaults to the repository name. Env: "+ComponentNameEnv)
	flags.String(ComponentVersionFlag, "", "Version of the subject component (metadata.component.version); defaults to the HEAD tag or commit. Env: "+ComponentVersionEnv)
	flags.String(ComponentTypeFlag, "", "Type of the subject component (metadata.component.type): "+strings.Join(cdx.ComponentTypes, ", ")+". Env: "+ComponentTypeEnv)
	flags.String(ComponentGroupFlag, "", "Group or namespace of the subject component (metadata.component.group). Env: "+ComponentGroupEnv)
	flags.String(ComponentPurlFlag, "", "Package URL of the subject component (metadata.component.purl). Env: "+ComponentPurlEnv)
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

// AuthoringInputsFromCommand reads everything the caller stated about the
// document's identity and content. A flag that was set wins; otherwise its
// environment variable is read. Values are parsed and checked here so a bad one
// fails before any work is done; what they mean is decided in internal/cdx.
func AuthoringInputsFromCommand(cmd *cobra.Command) (cdx.AuthoringInputs, error) {
	in := cdx.AuthoringInputs{Manufacturer: ManufacturerSourcesFromCommand(cmd)}
	phases, err := LifecycleOverrideFromCommand(cmd)
	if err != nil {
		return in, err
	}
	in.Lifecycle = phases
	if cmd == nil || cmd.Flags().Lookup(ManufacturerFlag) == nil {
		return in, nil
	}
	flags := cmd.Flags()

	in.ManufacturerURL = stringOrEnv(flags, ManufacturerURLFlag, ManufacturerURLEnv)
	in.SupplierName = stringOrEnv(flags, SupplierFlag, SupplierEnv)
	in.SupplierURL = stringOrEnv(flags, SupplierURLFlag, SupplierURLEnv)
	in.SerialNumber = stringOrEnv(flags, SerialFlag, SerialEnv)
	in.Component = cdx.ComponentOverride{
		Name:    stringOrEnv(flags, ComponentNameFlag, ComponentNameEnv),
		Version: stringOrEnv(flags, ComponentVersionFlag, ComponentVersionEnv),
		Type:    stringOrEnv(flags, ComponentTypeFlag, ComponentTypeEnv),
		Group:   stringOrEnv(flags, ComponentGroupFlag, ComponentGroupEnv),
		Purl:    stringOrEnv(flags, ComponentPurlFlag, ComponentPurlEnv),
	}
	if t := in.Component.Type; t != "" && !cdx.ValidComponentType(t) {
		return in, fmt.Errorf("--%s: %q is not a CycloneDX component type (one of %s)", ComponentTypeFlag, t, strings.Join(cdx.ComponentTypes, ", "))
	}

	if f := flags.Lookup(BOMVersionFlag); f != nil && f.Changed {
		n, _ := flags.GetInt(BOMVersionFlag)
		if n < 1 {
			return in, fmt.Errorf("--%s: %d is not a version of 1 or more", BOMVersionFlag, n)
		}
		in.BOMVersion = n
	} else if raw := strings.TrimSpace(os.Getenv(BOMVersionEnv)); raw != "" && raw != "0" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return in, fmt.Errorf("%s: %q is not a version of 1 or more", BOMVersionEnv, raw)
		}
		in.BOMVersion = n
	}

	for _, a := range listOrEnv(flags, AuthorFlag, AuthorsEnv) {
		c, err := parseAuthor(a)
		if err != nil {
			return in, fmt.Errorf("--%s: %w", AuthorFlag, err)
		}
		in.Authors = append(in.Authors, c)
	}
	for _, l := range listOrEnv(flags, LicenseFlag, LicensesEnv) {
		in.Licenses = append(in.Licenses, parseLicense(l))
	}
	for _, p := range listOrEnv(flags, PropertyFlag, PropertiesEnv) {
		name, value, ok := strings.Cut(p, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return in, fmt.Errorf("--%s: %q is not name=value", PropertyFlag, p)
		}
		if strings.HasPrefix(name, "vulnetix:") {
			return in, fmt.Errorf("--%s: %q is in the vulnetix: namespace, which only this product writes; use your own prefix", PropertyFlag, name)
		}
		in.Properties = append(in.Properties, cdx.Property{Name: name, Value: value})
	}
	for _, path := range listOrEnv(flags, OverlayFlag, OverlayEnv) {
		ov, err := cdx.LoadOverlay(path)
		if err != nil {
			return in, err
		}
		in.Overlays = append(in.Overlays, ov)
	}
	return in, nil
}

// stringOrEnv returns the flag's value when it was set, else the environment.
func stringOrEnv(flags *pflag.FlagSet, name, env string) string {
	if f := flags.Lookup(name); f != nil && f.Changed {
		v, _ := flags.GetString(name)
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(os.Getenv(env))
}

// listOrEnv returns a repeatable flag's values when it was set, else the
// environment variable split on commas and semicolons.
func listOrEnv(flags *pflag.FlagSet, name, env string) []string {
	var raw []string
	if f := flags.Lookup(name); f != nil && f.Changed {
		raw, _ = flags.GetStringArray(name)
	} else {
		raw = strings.FieldsFunc(os.Getenv(env), func(r rune) bool { return r == ',' || r == ';' })
	}
	var out []string
	for _, v := range raw {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseAuthor reads "Name <email>", "<email>", "email@host" or "Name".
func parseAuthor(s string) (cdx.OrganizationalContact, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return cdx.OrganizationalContact{}, fmt.Errorf("empty author")
	}
	if addr, err := mail.ParseAddress(s); err == nil {
		return cdx.OrganizationalContact{Name: addr.Name, Email: addr.Address}, nil
	}
	if strings.ContainsAny(s, "<>") {
		return cdx.OrganizationalContact{}, fmt.Errorf("%q is not 'Name <email>'", s)
	}
	return cdx.OrganizationalContact{Name: s}, nil
}

// parseLicense classifies a licence value the way CycloneDX distinguishes them:
// a recognised SPDX id goes to license.id, anything that reads as an SPDX
// expression (AND, OR, WITH, parentheses) to expression, and the rest to
// license.name.
func parseLicense(s string) cdx.LicenseChoice {
	s = strings.TrimSpace(s)
	if id := license.CanonicalSPDXID(s); id != "" {
		return cdx.LicenseChoice{License: &cdx.LicenseData{ID: id}}
	}
	upper := " " + strings.ToUpper(s) + " "
	if strings.ContainsAny(s, "()") || strings.Contains(upper, " AND ") || strings.Contains(upper, " OR ") || strings.Contains(upper, " WITH ") {
		return cdx.LicenseChoice{Expression: s}
	}
	return cdx.LicenseChoice{License: &cdx.LicenseData{Name: s}}
}
