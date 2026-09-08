package cmd

// Virtual patches and countermeasures — the defences Vulnetix derives from the
// PoC exploits it ingests.
//
//	vulnetix vdb virtual-patches get CVE-2021-44228
//	vulnetix vdb virtual-patches list --kind MODSECURITY --deploy-mode block
//	vulnetix vdb virtual-patches fetch <uuid> -o local.rules
//	vulnetix vdb countermeasures get CVE-2021-44228 --format sigma
//	vulnetix vdb countermeasures list --kind YARA --confidence HIGH
//
// Two parallel command trees over one implementation. They are separate
// commands rather than one with a --lane flag because they are separate
// products with separate quotas, and a SOC engineer looking for Sigma rules
// should not have to know that a Cloudflare expression lives behind the same
// noun.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

type defenceFlags struct {
	kinds         []string
	cveIDs        []string
	confidence    string
	deployMode    string
	exploitSource string
	q             string
	limit         int
	offset        int
	format        string
	output        string
}

var (
	virtualPatchFlags   defenceFlags
	countermeasureFlags defenceFlags
)

// defenceLaneCLI binds one command tree to one API lane.
type defenceLaneCLI struct {
	// rel is the API path segment and the JSON array key in the response.
	rel string
	// flags is the flag block this tree writes into.
	flags *defenceFlags
	// formats are the --format values that emit a raw body, in addition to
	// "json". Listed per lane so `--format sigma` is rejected on a virtual
	// patch rather than silently producing an empty file.
	formats []string
	// activity is the analytics/memory key prefix.
	activity string
}

var (
	virtualPatchLane = defenceLaneCLI{
		rel: "virtual-patches", flags: &virtualPatchFlags, activity: "virtual-patches",
		formats: []string{"snort", "suricata", "modsecurity", "nginx", "awswaf", "cloudflare", "regex"},
	}
	countermeasureLane = defenceLaneCLI{
		rel: "countermeasures", flags: &countermeasureFlags, activity: "countermeasures",
		formats: []string{"sigma", "yara", "stix", "openioc"},
	}
)

// formatKind maps a --format value onto the artifact kind it selects.
var formatKind = map[string]string{
	"snort": "SNORT", "suricata": "SURICATA", "modsecurity": "MODSECURITY",
	"nginx": "NGINX", "awswaf": "AWS_WAF", "cloudflare": "CLOUDFLARE_WAF",
	"regex": "REGEX_L7", "sigma": "SIGMA", "yara": "YARA",
	"stix": "STIX", "openioc": "OPENIOC",
}

func (l defenceLaneCLI) params() vdb.DefenceSearchParams {
	f := l.flags

	return vdb.DefenceSearchParams{
		Kinds:         upperAll(f.kinds),
		CveIDs:        upperAll(f.cveIDs),
		Confidence:    strings.ToUpper(strings.TrimSpace(f.confidence)),
		DeployMode:    strings.ToLower(strings.TrimSpace(f.deployMode)),
		ExploitSource: strings.TrimSpace(f.exploitSource),
		Q:             f.q,
		Limit:         f.limit,
		Offset:        f.offset,
	}
}

func (l defenceLaneCLI) summarise() string {
	f := l.flags
	parts := []string{}
	if len(f.kinds) > 0 {
		parts = append(parts, "kind="+strings.Join(f.kinds, ","))
	}
	if f.confidence != "" {
		parts = append(parts, "conf="+f.confidence)
	}
	if f.deployMode != "" {
		parts = append(parts, "mode="+f.deployMode)
	}
	if f.q != "" {
		parts = append(parts, "q="+f.q)
	}

	return strings.Join(parts, " ")
}

// emitDefences writes the response as JSON, or concatenates the rule bodies of
// one format so the output is a file the target tool can load directly.
func (l defenceLaneCLI) emit(cmd *cobra.Command, resp map[string]interface{}) error {
	format := strings.ToLower(strings.TrimSpace(l.flags.format))
	if format == "" || format == "json" {
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}

		return writeOutput(cmd, body, l.flags.output)
	}

	kind, known := formatKind[format]
	if !known || !contains(l.formats, format) {
		return fmt.Errorf("--format %s is not valid for %s; use json or one of %s",
			format, l.rel, strings.Join(l.formats, ", "))
	}

	items, _ := resp[l.rel].([]interface{})
	var b strings.Builder
	written := 0
	for _, it := range items {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		if k, _ := m["kind"].(string); k != kind {
			continue
		}
		raw, _ := m["rawText"].(string)
		if strings.TrimSpace(raw) == "" {
			// A Pro field the caller's plan withheld. Say so rather than
			// writing an empty file that looks like "there were no rules".
			continue
		}
		b.WriteString(strings.TrimRight(raw, "\n"))
		b.WriteString("\n")
		if kind == "SIGMA" {
			b.WriteString("---\n")
		}
		written++
	}
	if written == 0 {
		return fmt.Errorf("no %s rule bodies in the response; either none exist for this query or your plan does not include the rule text", kind)
	}

	return writeOutput(cmd, []byte(b.String()), l.flags.output)
}

func (l defenceLaneCLI) newTree(short, long string) *cobra.Command {
	parent := &cobra.Command{Use: l.rel, Short: short, Long: long}

	get := &cobra.Command{
		Use:   "get <CVE-ID>",
		Short: "Defences linked to a single advisory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(strings.TrimSpace(args[0]))
			client := newVDBClient()
			client.APIVersion = "/v2"

			var (
				resp map[string]interface{}
				err  error
			)
			if l.rel == "virtual-patches" {
				resp, err = client.V2VirtualPatches(id)
			} else {
				resp, err = client.V2Countermeasures(id)
			}
			if err != nil {
				return fmt.Errorf("%s get: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-get", id)

			return l.emit(cmd, resp)
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "Search the defence catalogue",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newVDBClient()
			client.APIVersion = "/v2"

			var (
				resp map[string]interface{}
				err  error
			)
			if l.rel == "virtual-patches" {
				resp, err = client.V2VirtualPatchSearch(l.params())
			} else {
				resp, err = client.V2CountermeasureSearch(l.params())
			}
			if err != nil {
				return fmt.Errorf("%s list: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-list", l.summarise())

			return l.emit(cmd, resp)
		},
	}

	fetch := &cobra.Command{
		Use:   "fetch <uuid>",
		Short: "Download one rule as the file its tool expects",
		Long: `Downloads a single artifact's body with the filename and content type
its target tool expects, so it can be loaded without editing.

  vulnetix vdb ` + l.rel + ` fetch 1a2b3c4d-… -o local.rules`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newVDBClient()
			client.APIVersion = "/v2"

			body, err := client.V2DefenceArchive(l.rel, strings.TrimSpace(args[0]))
			if err != nil {
				return fmt.Errorf("%s fetch: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-fetch", args[0])

			return writeOutput(cmd, body, l.flags.output)
		},
	}

	f := l.flags
	lf := list.Flags()
	lf.StringSliceVar(&f.kinds, "kind", nil,
		"Output format to return (repeat for OR): "+strings.Join(upperAll(l.formats), ", "))
	lf.StringSliceVar(&f.cveIDs, "cve-id", nil, "Limit to one or more advisory ids (repeat)")
	lf.StringVar(&f.confidence, "confidence", "", "HIGH | MEDIUM | LOW")
	lf.StringVar(&f.exploitSource, "exploit-source", "",
		"Source slug of the originating exploit, for example exploit-db or github-poc")
	lf.StringVar(&f.q, "match-content", "",
		"Free text over title, description and rule body (tokens AND)")
	lf.IntVar(&f.limit, "limit", 50, "Max items per page (1-200)")
	lf.IntVar(&f.offset, "offset", 0, "Pagination offset")
	if l.rel == "virtual-patches" {
		lf.StringVar(&f.deployMode, "deploy-mode", "",
			"Recommended starting mode: log | block")
	}

	for _, c := range []*cobra.Command{get, list} {
		c.Flags().StringVar(&f.format, "format", "json",
			"Output format: json, or "+strings.Join(l.formats, " | ")+" to emit that format's rule bodies")
	}
	for _, c := range []*cobra.Command{get, list, fetch} {
		c.Flags().StringVarP(&f.output, "output", "o", "",
			"Write the response to this file instead of stdout")
	}

	parent.AddCommand(get, list, fetch)

	return parent
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}

	return false
}

func init() {
	vdbCmd.AddCommand(virtualPatchLane.newTree(
		"Blocking defences derived from real exploits",
		`Virtual patches: rules that stop the exploit at an edge or an inline sensor,
derived from the proof-of-concept exploits Vulnetix ingests.

Formats: Snort, Suricata, nginx ModSecurity, AWS WAF, Cloudflare WAF and
layer-7 regex.

Per advisory:
  vulnetix vdb virtual-patches get CVE-2021-44228
  vulnetix vdb virtual-patches get CVE-2021-44228 --format modsecurity -o modsec.conf

Search the catalogue:
  vulnetix vdb virtual-patches list --kind AWS_WAF --deploy-mode block
  vulnetix vdb virtual-patches list --cve-id CVE-2021-44228 --confidence HIGH
  vulnetix vdb virtual-patches list --exploit-source exploit-db --format snort

Download one rule:
  vulnetix vdb virtual-patches fetch <uuid> -o local.rules

Every artifact names the exploit it was derived from, the confidence in it, the
mode it is safe to start in, and what it does not cover. Counts are available on
every plan; the rule bodies require Pro.`))

	vdbCmd.AddCommand(countermeasureLane.newTree(
		"Detection content derived from real exploits",
		`Countermeasures: detection content for a SIEM, an EDR or a threat platform,
derived from the proof-of-concept exploits Vulnetix ingests.

Formats: Sigma, YARA, STIX 2.1 and OpenIOC.

Per advisory:
  vulnetix vdb countermeasures get CVE-2021-44228
  vulnetix vdb countermeasures get CVE-2021-44228 --format sigma -o rules.yml

Search the catalogue:
  vulnetix vdb countermeasures list --kind YARA --confidence HIGH
  vulnetix vdb countermeasures list --cve-id CVE-2021-44228 --format stix
  vulnetix vdb countermeasures list --match-content "powershell"

Download one rule:
  vulnetix vdb countermeasures fetch <uuid> -o rule.yar

Every artifact names the exploit it was derived from, the confidence in it, and
what it does not cover. Counts are available on every plan; the rule bodies
require Pro.`))
}
