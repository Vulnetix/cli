package main

import (
	"fmt"
	"sort"
	"strings"
)

// probe is how actions-e2e.yml runs one action against testdata/action-fixture.
type probe struct {
	// With are inputs beyond the path, the binary and fail-on-findings.
	With map[string]string
	// AnyExit is for an action that needs credentials or a server the job does
	// not have. It still proves the action starts, builds its argv and finishes.
	AnyExit bool
	// Skip gives the reason an action cannot run in this job at all.
	Skip string
}

const fx = "${{ steps.fixture.outputs.dir }}"

// probes covers what the defaults cannot: every action not named here runs
// with its defaults and must exit 0.
var probes = map[string]probe{
	"setup":                    {Skip: "every other step installs through it"},
	"upload":                   {Skip: "publishes to Vulnetix; the release workflow uses it for real"},
	"gha-upload":               {Skip: "reads this run's artifacts and publishes them; vulnetix.yml uses it for real"},
	"tea-release":              {With: map[string]string{"tea-files": fx + "/.vulnetix/sast.sarif", "tea-dry-run": "true"}, AnyExit: true},
	"config-plan":              {With: map[string]string{"validate-only": "true"}},
	"config-apply":             {Skip: "changes live organisation configuration; config-plan validates the same documents"},
	"github-publish":           {With: map[string]string{"github-code-scanning": "false"}},
	"attest":                   {With: map[string]string{"subject": fx + "/.vulnetix/sast.sarif"}, AnyExit: true},
	"jail":                     {AnyExit: true},
	"vex":                      {AnyExit: true},
	"report":                   {AnyExit: true},
	"fix":                      {With: map[string]string{"extra-args": "--dry-run"}, AnyExit: true},
	"triage":                   {With: map[string]string{"provider": "vulnetix"}, AnyExit: true},
	"ignore-sync":              {AnyExit: true},
	"image":                    {With: map[string]string{"reference": "alpine:3.20", "no-upload": "true"}, AnyExit: true},
	"gha-workflows":            {With: map[string]string{"target": fx, "offline": "true"}},
	"gha-actions":              {With: map[string]string{"target": fx, "offline": "true"}},
	"gha-settings":             {With: map[string]string{"offline": "true"}, AnyExit: true},
	"gha-org":                  {With: map[string]string{"offline": "true"}, AnyExit: true},
	"gha-audit":                {With: map[string]string{"target": fx, "offline": "true"}},
	"gha-status":               {AnyExit: true},
	"github-advisories":        {With: map[string]string{"sarif": fx + "/.vulnetix/sast.sarif", "dry-run": "true"}, AnyExit: true},
	"bom-diff":                 {With: map[string]string{"before": fx + "/.vulnetix/sbom.cdx.json", "after": fx + "/.vulnetix/sbom.cdx.json"}},
	"bom-validate":             {With: map[string]string{"file": fx + "/.vulnetix/sbom.cdx.json"}},
	"bom-merge":                {With: map[string]string{"files": fx + "/.vulnetix/sbom.cdx.json\n" + fx + "/.vulnetix/sbom.cdx.json", "output-file": fx + "/.vulnetix/merged.cdx.json"}},
	"bom-enrich":               {With: map[string]string{"file": fx + "/.vulnetix/sbom.cdx.json", "output-file": fx + "/.vulnetix/enriched.cdx.json", "no-vulns": "true", "no-licenses": "true", "no-vex": "true"}},
	"api-discover":             {With: map[string]string{"target": fx, "no-upload": "true"}},
	"api-upload":               {With: map[string]string{"file": fx + "/.vulnetix/sast.sarif"}, AnyExit: true},
	"config-export":            {AnyExit: true},
	"jail-explain":             {AnyExit: true},
	"license-policy-validate":  {AnyExit: true},
	"license-exceptions-check": {AnyExit: true},
	"ai-firewall-apply":        {With: map[string]string{"dry-run": "true", "baseline-required": "false"}, AnyExit: true},
	"surface-liveness":         {AnyExit: true},
	"package-firewall":         {With: map[string]string{"ecosystem": "npm", "dry-run": "true"}, AnyExit: true},
}

// e2eWorkflow is .github/workflows/actions-e2e.yml: every action, run from this
// commit ($/ refs, which a locked workflow needs for a local action) against the branch's build. Steps run in one job so results written
// early (the SBOM) feed the actions that read them.
func e2eWorkflow() string {
	var b strings.Builder
	b.WriteString(header + `name: Actions Catalogue

on:
  pull_request:
    branches: [main]
    paths-ignore:
      - 'internal/sast/rules/**'
      - 'docs/**'
  workflow_dispatch:

concurrency:
  group: actions-e2e-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  catalogue:
    name: Every action
    runs-on: [self-hosted, Linux, X64, vulnetix-local]
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-go@v7
        with:
          go-version-file: go.mod

      - name: Configure private module fetch
        run: |
          go env -w GOPRIVATE=github.com/Vulnetix/vdb-sca-match,github.com/Vulnetix/vdb-manifest
          git config --global url."https://x-access-token:${{ secrets.PACKAGES_TOKEN }}@github.com/Vulnetix/vdb-sca-match".insteadOf "https://github.com/Vulnetix/vdb-sca-match"
          git config --global url."https://x-access-token:${{ secrets.PACKAGES_TOKEN }}@github.com/Vulnetix/vdb-manifest".insteadOf "https://github.com/Vulnetix/vdb-manifest"

      - name: Build the CLI
        run: go build -o "$RUNNER_TEMP/vulnetix" .
        env:
          CGO_ENABLED: "1"
          CGO_CFLAGS: "-w"

      - name: Prepare the fixture
        id: fixture
        run: |
          dir="$RUNNER_TEMP/catalogue-fixture"
          rm -rf "$dir"
          cp -r testdata/action-fixture "$dir"
          mv "$dir/vulnetix-config" "$dir/.vulnetix"
          echo "dir=$dir" >> "$GITHUB_OUTPUT"
          echo "bin=$RUNNER_TEMP/vulnetix" >> "$GITHUB_OUTPUT"
`)
	// The SBOM comes first: the bom-* actions read it.
	ordered := append([]action{}, actions...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name == "sbom" && ordered[j].Name != "sbom" })
	var check []string
	for _, a := range ordered {
		p := probes[a.Name]
		if p.Skip != "" {
			continue
		}
		id := "a_" + strings.ReplaceAll(a.Name, "-", "_")
		fmt.Fprintf(&b, "\n      - name: %s\n        id: %s\n        uses: $/%s\n        with:\n", dirOf(a), id, dirOf(a))
		b.WriteString("          binary-path: ${{ steps.fixture.outputs.bin }}\n          verify-provenance: 'false'\n          fail-on-findings: 'false'\n")
		if a.Path {
			fmt.Fprintf(&b, "          path: %s\n", fx)
		}
		keys := make([]string, 0, len(p.With))
		for k := range p.With {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(p.With[k], "\n") {
				fmt.Fprintf(&b, "          %s: |\n", k)
				for _, l := range strings.Split(p.With[k], "\n") {
					fmt.Fprintf(&b, "            %s\n", l)
				}
				continue
			}
			fmt.Fprintf(&b, "          %s: %s\n", k, p.With[k])
		}
		if !p.AnyExit {
			check = append(check, fmt.Sprintf("          expect %s \"${{ steps.%s.outputs.exit-code }}\"\n", a.Name, id))
		} else {
			check = append(check, fmt.Sprintf("          ran %s \"${{ steps.%s.outputs.exit-code }}\"\n", a.Name, id))
		}
	}
	b.WriteString(`
      - name: Every action ran
        shell: bash
        run: |
          bad=0
          # A scan exits 1 on findings over a gate, and no gate is set here, so 0
          # is the only pass. An action without credentials exits 1 or 2, and proves it
          # built its command and reached the CLI.
          expect() { if [ "$2" != 0 ]; then echo "::error::$1 exited $2"; bad=1; fi; }
          ran() { case "$2" in 0 | 1 | 2) ;; *) echo "::error::$1 exited '$2'"; bad=1 ;; esac; }
`)
	for _, c := range check {
		b.WriteString(c)
	}
	b.WriteString("          exit \"$bad\"\n")
	return b.String()
}
