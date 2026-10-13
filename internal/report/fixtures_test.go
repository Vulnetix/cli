package report

import (
	"time"

	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// fixedNow keeps expiry-dependent output stable.
var fixedNow = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

// plainTerm is a terminal with no colour, so assertions and golden files see
// exactly the characters and no escapes.
func plainTerm(width int, tty bool) *display.Terminal {
	return &display.Terminal{Width: width, Height: 40, IsTTY: tty}
}

type evOpt func(*scan.EnrichedVuln)

func vuln(id, pkg, ver, eco, sev, file string, opts ...evOpt) scan.EnrichedVuln {
	ev := scan.EnrichedVuln{
		VulnFinding: scan.VulnFinding{CveID: id, PackageName: pkg, PackageVer: ver, Ecosystem: eco, SourceFile: file, Severity: sev},
		MaxSeverity: sev, VersionStatus: "affected", Confirmed: true,
	}
	for _, o := range opts {
		o(&ev)
	}
	return ev
}

func withRange(r string) evOpt { return func(e *scan.EnrichedVuln) { e.AffectedRange = r } }
func withFix(v string) evOpt {
	return func(e *scan.EnrichedVuln) {
		e.Remediation = &scan.RemediationInfo{FixVersion: v, FixAvailability: "available"}
		e.FixAvailability = "available"
	}
}
func noFix() evOpt {
	return func(e *scan.EnrichedVuln) {
		e.FixAvailability = "no_fix"
		e.Remediation = &scan.RemediationInfo{FixAvailability: "no_fix"}
	}
}
func kev() evOpt { return func(e *scan.EnrichedVuln) { e.InCisaKev = true } }
func exploit(n int, weaponized bool) evOpt {
	return func(e *scan.EnrichedVuln) {
		e.ExploitIntel = &scan.ExploitSummary{ExploitCount: n, HasWeaponized: weaponized}
	}
}
func reach(kind, file string, line int) evOpt {
	return func(e *scan.EnrichedVuln) {
		e.Reachability = kind
		e.ReachabilityAssessed = true
		if file != "" {
			e.SemanticMatches = []scan.SemanticMatch{{File: file, Line: line}}
		}
	}
}
func assessed() evOpt { return func(e *scan.EnrichedVuln) { e.ReachabilityAssessed = true } }
func status(s string, confirmed bool) evOpt {
	return func(e *scan.EnrichedVuln) { e.VersionStatus = s; e.Confirmed = confirmed }
}

// sampleVulns is the scenario the design canvas draws.
func sampleVulns() []scan.EnrichedVuln {
	return []scan.EnrichedVuln{
		vuln("CVE-2021-44228", "log4j-core", "2.14.1", "maven", "critical", "pom.xml", withFix("2.17.1"), kev(), exploit(3, true), reach("direct", "", 0)),
		vuln("CVE-2021-45046", "log4j-core", "2.14.1", "maven", "critical", "pom.xml", withFix("2.16.0")),
		vuln("CVE-2021-45105", "log4j-core", "2.14.1", "maven", "high", "pom.xml", withFix("2.17.0")),
		vuln("CVE-2021-44832", "log4j-core", "2.14.1", "maven", "medium", "pom.xml", withFix("2.17.1")),
		vuln("CVE-2018-18074", "requests", "2.19.1", "pypi", "high", "requirements.txt", withFix("2.20.0"), exploit(1, false), reach("semantic", "api/client.py", 12)),
		vuln("CVE-2023-32681", "requests", "2.19.1", "pypi", "medium", "requirements.txt", withFix("2.31.0")),
		vuln("CVE-2020-14343", "pyyaml", "5.3", "pypi", "critical", "requirements.txt", withFix("5.4"), assessed()),
		vuln("CVE-2019-10906", "jinja2", "2.10", "pypi", "medium", "requirements.txt", withFix("2.10.1"), assessed()),
		vuln("CVE-2020-28493", "jinja2", "2.10", "pypi", "medium", "requirements.txt", withFix("2.11.3"), assessed()),
		vuln("CVE-2019-11324", "urllib3", "1.24.1", "pypi", "medium", "requirements.txt", withFix("1.24.2"), assessed()),
		vuln("CVE-2019-11236", "urllib3", "1.24.1", "pypi", "medium", "requirements.txt", withFix("1.24.3"), assessed()),
		// The kospex report, as it reads once the advisory record has been checked:
		// the range excludes the install and nothing contradicts it.
		vuln("PYSEC-2024-38", "fastapi", "0.135.1", "pypi", "medium", "requirements.txt",
			withRange("< 0.109.1"), withFix("0.109.1"), status("unknown", false)),
	}
}

// noFixVulns adds the findings that have no fix.
func noFixVulns() []scan.EnrichedVuln {
	return []scan.EnrichedVuln{
		vuln("CVE-2025-11111", "legacy-xml", "3.1.4", "pypi", "critical", "requirements.txt", noFix(), exploit(1, false), reach("semantic", "app/parse.py", 18)),
		vuln("CVE-2025-22222", "libexample", "1.8.2", "deb", "high", "Dockerfile", noFix(), exploit(1, false)),
		vuln("CVE-2025-33333", "otherlib", "4.0.0", "npm", "high", "package-lock.json", noFix(), kev()),
		vuln("CVE-2025-44444", "oldparser", "0.9.2", "cargo", "high", "Cargo.lock", noFix()),
	}
}
