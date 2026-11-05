package scanopts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func authoringCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "x", Run: func(*cobra.Command, []string) {}}
	AddAuthorshipFlags(cmd.Flags())
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return cmd
}

func TestAuthoringFlagsAreRegisteredOnce(t *testing.T) {
	cmd := authoringCmd(t)
	AddAuthorshipFlags(cmd.Flags()) // a second call is a no-op, not a panic
	for _, name := range AuthorshipFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("--%s not registered", name)
		}
		if _, ok := NotReplayed[name]; !ok {
			t.Errorf("--%s is not listed in NotReplayed; an explain run must not repeat it", name)
		}
	}
}

func TestAuthoringInputsFromFlags(t *testing.T) {
	cmd := authoringCmd(t,
		"--bom-manufacturer", "Acme Ltd", "--bom-manufacturer-url", "https://acme.example",
		"--bom-author", "Jane Doe <jane@acme.example>", "--bom-author", "Ops Team",
		"--bom-supplier", "Acme Supply", "--bom-supplier-url", "https://supply.acme.example",
		"--bom-serial", "release-1", "--bom-version", "3",
		"--bom-license", "Apache-2.0", "--bom-license", "MIT OR GPL-2.0-only", "--bom-license", "Acme Internal",
		"--bom-property", "acme:team=payments", "--bom-property", "acme:note=a=b",
		"--component-name", "svc", "--component-version", "2.0.0", "--component-type", "framework",
		"--component-group", "acme", "--component-purl", "pkg:generic/acme/svc@2.0.0",
		"--lifecycle", "build,operations",
	)
	in, err := AuthoringInputsFromCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if in.Manufacturer.Override != "Acme Ltd" || in.ManufacturerURL != "https://acme.example" {
		t.Errorf("manufacturer = %+v url %q", in.Manufacturer, in.ManufacturerURL)
	}
	if len(in.Authors) != 2 || in.Authors[0].Name != "Jane Doe" || in.Authors[0].Email != "jane@acme.example" || in.Authors[1].Name != "Ops Team" || in.Authors[1].Email != "" {
		t.Errorf("authors = %+v", in.Authors)
	}
	if in.SupplierName != "Acme Supply" || in.SupplierURL != "https://supply.acme.example" {
		t.Errorf("supplier = %q %q", in.SupplierName, in.SupplierURL)
	}
	if in.SerialNumber != "release-1" || in.BOMVersion != 3 {
		t.Errorf("serial/version = %q/%d", in.SerialNumber, in.BOMVersion)
	}
	if len(in.Licenses) != 3 || in.Licenses[0].License.ID != "Apache-2.0" || in.Licenses[1].Expression != "MIT OR GPL-2.0-only" || in.Licenses[2].License.Name != "Acme Internal" {
		t.Errorf("licences = %+v", in.Licenses)
	}
	if len(in.Properties) != 2 || in.Properties[1].Name != "acme:note" || in.Properties[1].Value != "a=b" {
		t.Errorf("properties = %+v", in.Properties)
	}
	if in.Component.Name != "svc" || in.Component.Version != "2.0.0" || in.Component.Type != "framework" || in.Component.Group != "acme" || in.Component.Purl != "pkg:generic/acme/svc@2.0.0" {
		t.Errorf("component = %+v", in.Component)
	}
	if len(in.Lifecycle) != 2 {
		t.Errorf("lifecycle = %v", in.Lifecycle)
	}
}

func TestAuthoringInputsFromEnvironment(t *testing.T) {
	t.Setenv(AuthorsEnv, "A <a@x.example>; B")
	t.Setenv(SupplierEnv, "Env Supply")
	t.Setenv(SerialEnv, "env-serial")
	t.Setenv(BOMVersionEnv, "2")
	t.Setenv(LicensesEnv, "MIT,Apache-2.0")
	t.Setenv(PropertiesEnv, "acme:a=1,acme:b=2")
	t.Setenv(ComponentNameEnv, "env-name")
	t.Setenv(ComponentTypeEnv, "library")

	t.Run("environment fills unset flags", func(t *testing.T) {
		in, err := AuthoringInputsFromCommand(authoringCmd(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Authors) != 2 || in.Authors[0].Email != "a@x.example" || in.Authors[1].Name != "B" {
			t.Errorf("authors = %+v", in.Authors)
		}
		if in.SupplierName != "Env Supply" || in.SerialNumber != "env-serial" || in.BOMVersion != 2 {
			t.Errorf("supplier/serial/version = %q/%q/%d", in.SupplierName, in.SerialNumber, in.BOMVersion)
		}
		if len(in.Licenses) != 2 || len(in.Properties) != 2 {
			t.Errorf("licences = %+v properties = %+v", in.Licenses, in.Properties)
		}
		if in.Component.Name != "env-name" || in.Component.Type != "library" {
			t.Errorf("component = %+v", in.Component)
		}
	})

	t.Run("a set flag beats the environment", func(t *testing.T) {
		in, err := AuthoringInputsFromCommand(authoringCmd(t, "--bom-author", "Flag <f@x.example>", "--bom-supplier", "Flag Supply", "--bom-version", "9"))
		if err != nil {
			t.Fatal(err)
		}
		if len(in.Authors) != 1 || in.Authors[0].Name != "Flag" {
			t.Errorf("authors = %+v", in.Authors)
		}
		if in.SupplierName != "Flag Supply" || in.BOMVersion != 9 {
			t.Errorf("supplier/version = %q/%d", in.SupplierName, in.BOMVersion)
		}
	})
}

func TestAuthoringInputsRejectBadValues(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--bom-version", "0"}, "--bom-version"},
		{[]string{"--bom-version", "-2"}, "--bom-version"},
		{[]string{"--component-type", "thing"}, "not a CycloneDX component type"},
		{[]string{"--bom-property", "novalue"}, "name=value"},
		{[]string{"--bom-property", "vulnetix:scope=x"}, "vulnetix: namespace"},
		{[]string{"--bom-author", "Broken <"}, "Name <email>"},
		{[]string{"--bom-overlay", filepath.Join(t.TempDir(), "missing.json")}, "missing.json"},
		{[]string{"--lifecycle", "nope"}, "--lifecycle"},
	}
	for _, c := range cases {
		cmd := authoringCmd(t, c.args...)
		_, err := AuthoringInputsFromCommand(cmd)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: want error containing %q, got %v", c.args, c.want, err)
		}
	}
	// --bom-version 0 from the environment means unset, not invalid.
	t.Setenv(BOMVersionEnv, "0")
	if _, err := AuthoringInputsFromCommand(authoringCmd(t)); err != nil {
		t.Errorf("VULNETIX_BOM_VERSION=0: %v", err)
	}
}

func TestAuthoringInputsLoadOverlays(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.json")
	two := filepath.Join(dir, "two.json")
	if err := os.WriteFile(one, []byte(`{"metadata":{"supplier":{"name":"One"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte(`{"metadata":{"supplier":{"name":"Two"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := AuthoringInputsFromCommand(authoringCmd(t, "--bom-overlay", one, "--bom-overlay", two))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Overlays) != 2 || in.Overlays[1].BOM.Metadata.Supplier.Name != "Two" || in.Overlays[1].Path != two {
		t.Errorf("overlays = %+v", in.Overlays)
	}
}

func TestCommandsWithoutTheFlagsDoNotPanic(t *testing.T) {
	cmd := &cobra.Command{Use: "reader"}
	in, err := AuthoringInputsFromCommand(cmd)
	if err != nil || in.SerialNumber != "" {
		t.Errorf("got %+v, %v", in, err)
	}
	if _, err := AuthoringInputsFromCommand(nil); err != nil {
		t.Error(err)
	}
}
