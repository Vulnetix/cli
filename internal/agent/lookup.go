package agent

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/Vulnetix/vdb-sca-match/parse"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/cache"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// lookupTimeout bounds the whole guard.
//
// A hook sits between an agent and the tool it asked to run, so the budget is
// the user's patience rather than the server's. Well under the hosts' own hook
// timeouts, and short enough that a slow network degrades into "nothing known"
// rather than a stalled agent.
const lookupTimeout = 12 * time.Second

// Lookup answers what is known about a set of packages.
//
// An interface so the decision logic can be exercised without a network, which
// is most of what the guard's tests do: what to say is a policy question and
// should not need a credential to answer.
type Lookup interface {
	Assess(ctx context.Context, cands []Candidate) []Assessment
}

// Auth reports how the CLI is authenticated, so the guard can say when it is
// running on the shared pool.
type Auth struct {
	// Community is true when no credential of the user's own was found and the
	// built-in Community credentials are in use.
	Community bool
	// Missing is true when there is no credential at all, community included.
	Missing bool
}

// VDBLookup is the real lookup, against cli.sca.
type VDBLookup struct {
	Root       string
	CLIVersion string

	// client is built on first use so a guard that finds nothing to ask about
	// never constructs one, and a credential change is picked up next time.
	client *vdb.Client
	auth   Auth
}

// NewVDBLookup prepares a lookup rooted at a repository.
func NewVDBLookup(root, cliVersion string) *VDBLookup {
	return &VDBLookup{Root: root, CLIVersion: cliVersion}
}

// AuthState reports the credential the lookup resolved.
func (l *VDBLookup) AuthState() Auth { return l.auth }

// Warm resolves the credential without asking a question.
//
// AuthState is only meaningful once a client has been built, and building one
// happens lazily inside Assess. A caller that wants the credential state and
// nothing else — capability detection, an installer reporting what it wired —
// would otherwise have to make a pointless query to find out.
func (l *VDBLookup) Warm() {
	_, _ = l.ensureClient()
}

// Assess looks up every candidate in one request.
//
// Every failure path returns Unknown rather than an error. The caller is a hook
// standing between an agent and its tool call: there is nothing useful to do
// with an error, and reporting one would be claiming something about a package
// that was never checked.
func (l *VDBLookup) Assess(ctx context.Context, cands []Candidate) []Assessment {
	out := make([]Assessment, 0, len(cands))
	for _, c := range cands {
		out = append(out, Assessment{Candidate: c, Unknown: true})
	}
	if len(cands) == 0 {
		return out
	}

	client, err := l.ensureClient()
	if err != nil || client == nil {
		return out
	}

	packages := make([]scan.ScopedPackage, 0, len(cands))
	for _, c := range cands {
		packages = append(packages, scan.ScopedPackage{
			Name:      c.Name,
			Version:   versionForQuery(c.Version),
			Ecosystem: c.Ecosystem,
			Scope:     parse.ScopeProduction,
		})
	}

	purlByIndex := make([]string, len(packages))
	unique := make([]string, 0, len(packages))
	seen := map[string]bool{}
	for i, p := range packages {
		purl := cdx.BuildLocalPurl(p.Name, p.Version, p.Ecosystem)
		purlByIndex[i] = purl
		if purl == "" || seen[purl] {
			continue
		}
		seen[purl] = true
		unique = append(unique, purl)
	}
	if len(unique) == 0 {
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	resp, err := client.CliSCAWithContext(ctx, vdb.SnapshotEnv(l.Root, l.CLIVersion, "", ""), vdb.CliSCARequest{
		Purls: unique,
		Options: vdb.CliSCAOptions{
			// Reachability is a whole-tree analysis and this is a question about
			// a package that is not installed yet, so it has nothing to walk.
			IncludeReachability: boolPtr(false),
			IncludeSafeVersions: true,
			IncludeEOL:          true,
			IncludeMalware:      true,
			// The version list is what resolves an unversioned install below.
			IncludeVersionLag: true,
		},
	})
	if err != nil || resp == nil {
		return out
	}

	_, enriched, _ := scan.SynthesiseFromCDX(resp.Data.CycloneDX, packages, purlByIndex)

	insightByPurl := make(map[string]*vdb.CliPackageInsight, len(resp.Data.PackageInsights))
	for i := range resp.Data.PackageInsights {
		in := &resp.Data.PackageInsights[i]
		insightByPurl[strings.ToLower(in.Purl)] = in
	}

	// Findings carry a package name and ecosystem rather than a purl, so the
	// join is on the coordinate the synthesiser records.
	vulnsByPkg := make(map[string][]scan.EnrichedVuln, len(unique))
	for _, v := range enriched {
		vulnsByPkg[pkgKey(v.PackageName, v.Ecosystem)] = append(vulnsByPkg[pkgKey(v.PackageName, v.Ecosystem)], v)
	}

	for i := range out {
		purl := strings.ToLower(purlByIndex[i])
		if purl == "" {
			continue
		}
		out[i].Unknown = false
		out[i].Vulns = vulnsByPkg[pkgKey(cands[i].Name, cands[i].Ecosystem)]
		out[i].ExploitsGated = resp.Meta.TierGated["exploits"]
		if in, ok := insightByPurl[purl]; ok {
			out[i].Insight = in
			out[i].Resolved = in.Version
		}
	}

	return l.resolveUnversioned(ctx, client, cands, out)
}

// resolveUnversioned re-assesses `npm i express` as the version it installs.
//
// A version-less purl asks the server about the package as a whole, and the
// answer to "is any published version of express malicious" is yes: one
// compromised release, years ago, is on the OSS malicious-packages list. The
// first pass therefore came back `isMalicious: true` for `pkg:npm/express`
// and the guard refused `npm i express` outright — while `express@5.1.0`,
// which is what that command installs, is clean.
//
// So a candidate that named no version is resolved to the newest published
// version from the first pass and assessed again as that concrete purl. A
// typosquat's newest version is still malicious and is still refused; a real
// package with one bad release in its history is judged on the release that
// would actually land. Where the newest version cannot be determined the
// bare-name verdict is kept but marked NameLevel, and the guard reports it
// instead of blocking on it.
func (l *VDBLookup) resolveUnversioned(ctx context.Context, client *vdb.Client, cands []Candidate, out []Assessment) []Assessment {
	type retry struct {
		index   int
		purl    string
		version string
	}
	var retries []retry
	purls := make([]string, 0, 4)

	for i := range out {
		if out[i].Unknown || versionForQuery(cands[i].Version) != "" {
			continue
		}
		in := out[i].Insight
		if in == nil || len(in.LatestVersions) == 0 || in.LatestVersions[0].Version == "" {
			// Nothing to resolve to. Whatever the bare name said stands, but as a
			// name-level fact rather than a verdict on what will install.
			out[i].NameLevel = true
			continue
		}
		latest := in.LatestVersions[0].Version
		purl := cdx.BuildLocalPurl(cands[i].Name, latest, cands[i].Ecosystem)
		if purl == "" {
			out[i].NameLevel = true
			continue
		}
		retries = append(retries, retry{index: i, purl: purl, version: latest})
		purls = append(purls, purl)
	}
	if len(retries) == 0 {
		return out
	}

	packages := make([]scan.ScopedPackage, 0, len(retries))
	purlByIndex := make([]string, 0, len(retries))
	for _, rt := range retries {
		c := cands[rt.index]
		packages = append(packages, scan.ScopedPackage{
			Name:      c.Name,
			Version:   rt.version,
			Ecosystem: c.Ecosystem,
			Scope:     parse.ScopeProduction,
		})
		purlByIndex = append(purlByIndex, rt.purl)
	}

	resp, err := client.CliSCAWithContext(ctx, vdb.SnapshotEnv(l.Root, l.CLIVersion, "", ""), vdb.CliSCARequest{
		Purls: purls,
		Options: vdb.CliSCAOptions{
			IncludeReachability: boolPtr(false),
			IncludeSafeVersions: true,
			IncludeEOL:          true,
			IncludeMalware:      true,
		},
	})
	if err != nil || resp == nil {
		// The second look failed. The first answer is all there is; say it is
		// about the name, not the install.
		for _, rt := range retries {
			out[rt.index].NameLevel = true
		}
		return out
	}

	_, enriched, _ := scan.SynthesiseFromCDX(resp.Data.CycloneDX, packages, purlByIndex)

	insightByPurl := make(map[string]*vdb.CliPackageInsight, len(resp.Data.PackageInsights))
	for i := range resp.Data.PackageInsights {
		in := &resp.Data.PackageInsights[i]
		insightByPurl[strings.ToLower(in.Purl)] = in
	}
	vulnsByPkg := make(map[string][]scan.EnrichedVuln)
	for _, v := range enriched {
		k := pkgKey(v.PackageName, v.Ecosystem)
		vulnsByPkg[k] = append(vulnsByPkg[k], v)
	}

	for _, rt := range retries {
		c := cands[rt.index]
		out[rt.index].Vulns = vulnsByPkg[pkgKey(c.Name, c.Ecosystem)]
		if in, ok := insightByPurl[strings.ToLower(rt.purl)]; ok {
			out[rt.index].Insight = in
			out[rt.index].Resolved = in.Version
		} else {
			out[rt.index].NameLevel = true
		}
	}
	return out
}

// pkgKey is the case-insensitive coordinate a finding and a candidate are
// joined on.
func pkgKey(name, ecosystem string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" + strings.ToLower(strings.TrimSpace(name))
}

// versionForQuery turns a requested spec into something a purl can carry.
//
// A range or a dist-tag is not a version the server can match, so it is dropped
// and the server answers about the package rather than about a version that
// does not exist. What actually resolves comes back as the insight's version.
func versionForQuery(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || isUnpinned(v) {
		return ""
	}
	return v
}

// ensureClient builds the VDB client, mirroring how the language server does it
// so the editor and the agent resolve the same credentials, honour the same API
// override and share the same on-disk cache.
//
// Signing in is not required: the CLI ships community credentials, and a guard
// that only worked for authenticated users would be off for most first runs.
func (l *VDBLookup) ensureClient() (*vdb.Client, error) {
	if l.client != nil {
		return l.client, nil
	}

	creds, err := auth.LoadCredentials()
	switch {
	case err != nil || creds == nil:
		creds = auth.CommunityCredentials()
		l.auth = Auth{Community: true}
	case auth.IsCommunity(creds):
		l.auth = Auth{Community: true}
	}
	if creds == nil {
		l.auth = Auth{Missing: true}
		return nil, nil
	}

	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if u := strings.TrimSpace(os.Getenv("VULNETIX_API_URL")); u != "" {
		client.BaseURL = strings.TrimRight(u, "/")
	}
	if client.HTTPClient != nil {
		// Generous relative to the lookup deadline: this client also fetches the
		// auth token, and starving that would fail the guard for a reason that
		// has nothing to do with how long the query takes.
		client.HTTPClient.Timeout = lookupTimeout + 20*time.Second
	}
	if dc, cacheErr := cache.NewDiskCache(l.cliVersion()); cacheErr == nil {
		client.Cache = dc
	}

	l.client = client
	return client, nil
}

// cliVersion namespaces the on-disk cache, matching what the language server
// uses so the editor and the agent share entries rather than each paying for
// the same lookup.
func (l *VDBLookup) cliVersion() string {
	if strings.TrimSpace(l.CLIVersion) == "" {
		return "dev"
	}
	return l.CLIVersion
}

func boolPtr(b bool) *bool { return &b }
