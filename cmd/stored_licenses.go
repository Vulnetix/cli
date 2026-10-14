package cmd

import (
	"context"
	"time"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// storedLicensesTimeout bounds the API lookup; past it the scan resolves the
// licences itself, as it did before the lookup existed.
const storedLicensesTimeout = 10 * time.Second

// lookupStoredLicenses asks the API for the licences earlier scans resolved for
// packages, keyed as persistence keys a Dependency row: the package's purl, or
// name@version when it has none (see buildCliPackages and PersistCliSCA).
func lookupStoredLicenses(packages []license.PackageLicense) map[int]string {
	client := newCliClient()
	if client == nil {
		return nil
	}
	keys := make([]string, len(packages))
	for i, p := range packages {
		keys[i] = cdx.BuildLocalPurl(p.PackageName, p.PackageVersion, p.Ecosystem)
		if keys[i] == "" {
			keys[i] = p.PackageName + "@" + p.PackageVersion
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), storedLicensesTimeout)
	defer cancel()
	resp, err := client.CliLicenses(ctx, envForCli(), vdb.CliLicensesRequest{Keys: keys})
	if err != nil || resp == nil {
		return nil
	}
	out := map[int]string{}
	for i, k := range keys {
		if lic := resp.Data.Licenses[k]; lic != "" {
			out[i] = lic
		}
	}
	return out
}
