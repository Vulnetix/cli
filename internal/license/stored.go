package license

// StoredLicenses, when set, returns licences the Vulnetix API already holds for
// some of packages (earlier scans store the licence they resolved), keyed by
// the package's index in the slice. The cmd layer sets it; nil (no API, or the
// command does not use one) skips the step.
//
// It runs after local detection and before the registry, deps.dev and GitHub
// lookups, so a package any scan has resolved costs no third-party round trip;
// those lookups still run for every package it leaves UNKNOWN.
var StoredLicenses func(packages []PackageLicense) map[int]string

func applyStoredLicenses(packages []PackageLicense) {
	if StoredLicenses == nil {
		return
	}
	set := func(p *PackageLicense, lic string) {
		p.LicenseSpdxID = lic
		p.LicenseSource = "vulnetix"
		if ids := ParseSPDXExpression(lic); len(ids) > 0 {
			p.Record = LookupSPDX(ids[0])
		}
	}
	// An answer the API gave before is kept in the local licence store, so a
	// repeat scan asks the API only about packages it has no answer for.
	var idx []int
	var unknown []PackageLicense
	for i, p := range packages {
		if p.LicenseSpdxID != "" && p.LicenseSpdxID != "UNKNOWN" {
			continue
		}
		if lic, ok := loadStoredLicense("vulnetix", storedLicenseKey(p)); ok {
			set(&packages[i], lic)
			continue
		}
		idx = append(idx, i)
		unknown = append(unknown, p)
	}
	if len(unknown) == 0 {
		return
	}
	for j, lic := range StoredLicenses(unknown) {
		if j < 0 || j >= len(idx) || lic == "" {
			continue
		}
		set(&packages[idx[j]], lic)
		storeLicense("vulnetix", storedLicenseKey(packages[idx[j]]), lic)
	}
}

func storedLicenseKey(p PackageLicense) string {
	return p.Ecosystem + ":" + p.PackageName + ":" + p.PackageVersion
}
