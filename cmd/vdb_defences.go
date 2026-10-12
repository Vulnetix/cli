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
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
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
	in            inputFlags
	file          string
	countsFormat  string
}

// outputFormats are the values of -o that name a format, as everywhere else in
// vdb. Any other value is a file to write the response to.
var outputFormats = map[string]bool{"json": true, "pretty": true, "table": true}

// target splits -o into a format name and a file path.
func (f *defenceFlags) target() (format, path string) {
	o := strings.TrimSpace(f.output)
	if outputFormats[strings.ToLower(o)] {
		return strings.ToLower(o), ""
	}
	return "", o
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

func (l defenceLaneCLI) params(stdin io.Reader) (vdb.DefenceSearchParams, error) {
	f := l.flags
	in, err := f.in.inputs(stdin)
	if err != nil {
		return vdb.DefenceSearchParams{}, err
	}

	return vdb.DefenceSearchParams{
		Inputs:        in,
		Kinds:         upperAll(f.kinds),
		CveIDs:        upperAll(f.cveIDs),
		Confidence:    strings.ToUpper(strings.TrimSpace(f.confidence)),
		DeployMode:    strings.ToLower(strings.TrimSpace(f.deployMode)),
		ExploitSource: strings.TrimSpace(f.exploitSource),
		Q:             f.q,
		Limit:         f.limit,
		Offset:        f.offset,
	}, nil
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

		_, path := l.flags.target()
		return writeOutput(cmd, body, path)
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

	_, path := l.flags.target()
	return writeOutput(cmd, []byte(b.String()), path)
}

func (l defenceLaneCLI) newTree(short, long string) *cobra.Command {
	parent := &cobra.Command{Use: l.rel, Short: short, Long: long}

	get := &cobra.Command{
		Use:   "get [input]",
		Short: "Defences for an advisory, a package, a product or any other input",
		Long: `Defences for one input: a vulnerability id, a purl, a CPE, a TEI or a SWID
tag file as the argument, or any input-kind flag. Flags given with the argument
narrow it further.

  vulnetix vdb ` + l.rel + ` get CVE-2021-44228
  vulnetix vdb ` + l.rel + ` get pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
  vulnetix vdb ` + l.rel + ` get cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
  vulnetix vdb ` + l.rel + ` get urn:tei:purl:vulnetix.com:pkg:npm/lodash@4.17.20
  vulnetix vdb ` + l.rel + ` get ./log4j.swidtag
  vulnetix vdb ` + l.rel + ` get --vendor apache --product log4j --package-version 2.14.1
  vulnetix vdb ` + l.rel + ` get --cel "component.name.startsWith('log4j')"`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flagged, err := l.flags.in.inputs(cmd.InOrStdin())
			if err != nil {
				return err
			}
			in := flagged
			if len(args) == 1 {
				fromArg, err := detectInput(args[0])
				if err != nil {
					return err
				}
				in = mergeInputs(fromArg, flagged)
			}
			if in.Empty() {
				return fmt.Errorf("name what to find defences for: an argument (CVE id, purl, CPE, TEI, SWID tag file) or an input flag such as --purl or --product")
			}
			client := newVDBClient()
			client.APIVersion = "/v2"

			// One identifier the per-vulnerability route reads keeps that route
			// and its envelope; anything else is a catalogue search.
			var resp map[string]interface{}
			if id, ok := pathIdentifier(in); ok {
				resp, err = client.V2VulnDefences(l.rel, id)
			} else {
				resp, err = client.V2DefenceSearch(l.rel, vdb.DefenceSearchParams{Inputs: in, Limit: 200})
			}
			if err != nil {
				return fmt.Errorf("%s get: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-get", in.Label())

			return l.emit(cmd, resp)
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "Search the defence catalogue by any input kind",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := l.params(cmd.InOrStdin())
			if err != nil {
				return err
			}
			client := newVDBClient()
			client.APIVersion = "/v2"

			resp, err := client.V2DefenceSearch(l.rel, p)
			if err != nil {
				return fmt.Errorf("%s list: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-list", strings.TrimSpace(l.summarise()+" "+p.Inputs.Label()))

			return l.emit(cmd, resp)
		},
	}

	counts := &cobra.Command{
		Use:   "counts [input...]",
		Short: "Count defences for many inputs at once",
		Long: `Counts the ` + l.rel + ` for each input, in one request per 100 inputs.
Each argument is one input (a vulnerability id, purl, CPE, TEI or SWID tag
file); the input-kind flags make one more; --file reads one input per line,
either as an argument would be written or as a JSON object of inputs with an
optional "key". Counts are on every plan; with Pro each defence is listed with
the console link that opens it.

  vulnetix vdb ` + l.rel + ` counts CVE-2021-44228 pkg:npm/lodash@4.17.20
  vulnetix vdb ` + l.rel + ` counts --file inputs.txt
  cat inputs.jsonl | vulnetix vdb ` + l.rel + ` counts --file -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			items, err := l.countItems(cmd, args)
			if err != nil {
				return err
			}
			client := newVDBClient()
			client.APIVersion = "/v2"
			resp, err := client.V2DefenceCounts(items)
			if err != nil {
				return fmt.Errorf("%s counts: %w", l.rel, err)
			}
			printRateLimit(client)
			recordVDBQuery(l.activity+"-counts", fmt.Sprintf("%d inputs", len(items)))

			format, path := l.flags.target()
			if strings.EqualFold(l.flags.countsFormat, "json") || format == "json" || path != "" {
				body, err := json.MarshalIndent(resp, "", "  ")
				if err != nil {
					return err
				}
				return writeOutput(cmd, body, path)
			}
			l.printCounts(cmd, resp)
			return nil
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

			_, path := l.flags.target()
			return writeOutput(cmd, body, path)
		},
	}

	f := l.flags
	lf := list.Flags()
	lf.StringSliceVar(&f.kinds, "kind", nil,
		"Output format to return (repeat for OR): "+strings.Join(upperAll(l.formats), ", "))
	lf.StringSliceVar(&f.cveIDs, "cve-id", nil, "Limit to one or more advisory ids (repeat); the same as --vuln-id")
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
	for _, c := range []*cobra.Command{get, list, counts} {
		addInputFlags(c.Flags(), &f.in)
	}
	counts.Flags().StringVar(&f.file, "file", "", "Read one input per line from this file (- for stdin)")
	counts.Flags().StringVar(&f.countsFormat, "format", "table", "Output format: table or json")
	for _, c := range []*cobra.Command{get, list, fetch, counts} {
		c.Flags().StringVarP(&f.output, "output", "o", "",
			"Output format (json, pretty, table), or a file to write the response to")
	}

	parent.AddCommand(get, list, fetch, counts)

	return parent
}

// pathIdentifier reports the single identifier the per-vulnerability route can
// take in its path (one vulnerability id, purl, CPE or TEI, and nothing else).
func pathIdentifier(in vdb.Inputs) (string, bool) {
	kinds := in.Kinds()
	if len(kinds) != 1 {
		return "", false
	}
	switch kinds[0] {
	case "vulnId":
		if len(in.VulnIDs) == 1 {
			return strings.TrimSpace(in.VulnIDs[0]), true
		}
	case "purl":
		return in.PURL, true
	case "cpe":
		return in.CPE, true
	case "tei":
		return in.TEI, true
	}
	return "", false
}

// countItems gathers the inputs for counts: each argument, the flags as one
// more, and every line of --file.
func (l defenceLaneCLI) countItems(cmd *cobra.Command, args []string) ([]vdb.DefenceCountsItem, error) {
	var items []vdb.DefenceCountsItem
	for _, a := range args {
		in, err := detectInput(a)
		if err != nil {
			return nil, err
		}
		items = append(items, vdb.DefenceCountsItem{Key: a, Inputs: in})
	}
	flagged, err := l.flags.in.inputs(cmd.InOrStdin())
	if err != nil {
		return nil, err
	}
	if !flagged.Empty() {
		items = append(items, vdb.DefenceCountsItem{Key: flagged.Label(), Inputs: flagged})
	}
	if path := strings.TrimSpace(l.flags.file); path != "" {
		var r io.Reader = cmd.InOrStdin()
		if path != "-" {
			f, err := os.Open(path)
			if err != nil {
				return nil, fmt.Errorf("--file: %w", err)
			}
			defer f.Close()
			r = f
		}
		more, err := readInputLines(r)
		if err != nil {
			return nil, fmt.Errorf("--file %s: %w", path, err)
		}
		items = append(items, more...)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("name what to count defences for: arguments, an input flag, or --file")
	}
	return items, nil
}

// printCounts writes one block per input: this lane's total by kind and, with
// Pro, each defence with the console link that opens it.
func (l defenceLaneCLI) printCounts(cmd *cobra.Command, resp *vdb.DefenceCountsResponse) {
	out := cmd.OutOrStdout()
	term := display.NewTerminal()
	noun := strings.ReplaceAll(l.rel, "-", " ")
	for _, item := range resp.Items {
		if item.Error != nil {
			fmt.Fprintf(out, "%s\n  error: %s\n", item.Key, item.Error.Error())
			continue
		}
		lane := item.VirtualPatches
		if l.rel == "countermeasures" {
			lane = item.Countermeasures
		}
		if lane == nil {
			lane = &vdb.DefenceLaneCounts{}
		}
		fmt.Fprintf(out, "%s\n  %d %s%s\n", item.Key, lane.Total, noun, byKindSummary(lane.ByKind))
		for _, d := range lane.Defences {
			fmt.Fprintf(out, "    %-15s %-6s %-6s %s\n      %s\n", d.Kind, d.DeployMode, d.Confidence, d.Title,
				term.Hyperlink(d.ConsoleURL, d.ConsoleURL))
		}
		if lane.HasMore {
			fmt.Fprintf(out, "    … %d more; list them with: vulnetix vdb %s list %s\n", lane.Total-len(lane.Defences), l.rel, item.Key)
		}
	}
	if resp.Gated() && countsTotal(resp, l.rel) > 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "\nThe rule text and the console links are included with Pro: https://www.vulnetix.com/pricing")
	}
}

// byKindSummary renders a kind count map as " (SNORT 2 · AWS_WAF 1)".
func byKindSummary(byKind map[string]int) string {
	if len(byKind) == 0 {
		return ""
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%s %d", k, byKind[k])
	}
	return " (" + strings.Join(parts, " · ") + ")"
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

For an advisory, a package, a product or anything else you hold:
  vulnetix vdb virtual-patches get CVE-2021-44228
  vulnetix vdb virtual-patches get pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
  vulnetix vdb virtual-patches get cpe:2.3:o:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*
  vulnetix vdb virtual-patches get CVE-2021-44228 --format modsecurity -o modsec.conf

Search the catalogue by any input kind:
  vulnetix vdb virtual-patches list --kind AWS_WAF --deploy-mode block
  vulnetix vdb virtual-patches list --vendor "Palo Alto Networks" --product PAN-OS --package-version 11.1.0
  vulnetix vdb virtual-patches list --tei urn:tei:uuid:vulnetix.com:<uuid>
  vulnetix vdb virtual-patches list --exploit-source exploit-db --format snort

Count for many inputs at once:
  vulnetix vdb virtual-patches counts CVE-2024-3400 pkg:npm/lodash@4.17.20
  vulnetix vdb virtual-patches counts --file inputs.txt

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

For an advisory, a package, a product or anything else you hold:
  vulnetix vdb countermeasures get CVE-2021-44228
  vulnetix vdb countermeasures get pkg:npm/lodash@4.17.20
  vulnetix vdb countermeasures get CVE-2021-44228 --format sigma -o rules.yml

Search the catalogue by any input kind:
  vulnetix vdb countermeasures list --kind YARA --confidence HIGH
  vulnetix vdb countermeasures list --cel "component.ecosystem == 'npm'" --format stix
  vulnetix vdb countermeasures list --swid ./product.swidtag
  vulnetix vdb countermeasures list --match-content "powershell"

Count for many inputs at once:
  vulnetix vdb countermeasures counts --file inputs.jsonl

Download one rule:
  vulnetix vdb countermeasures fetch <uuid> -o rule.yar

Every artifact names the exploit it was derived from, the confidence in it, and
what it does not cover. Counts are available on every plan; the rule bodies
require Pro.

Inputs: a vulnerability id, --package with --ecosystem and --package-version,
--purl, --vendor with --product, --cpe, --swid, --tei or --cel. Kinds given
together narrow the answer; the response says what each was read as.`))
}

// countsTotal sums the lane's totals, so the upgrade note only appears when
// Pro would show something.
func countsTotal(resp *vdb.DefenceCountsResponse, rel string) int {
	n := 0
	for _, item := range resp.Items {
		lane := item.VirtualPatches
		if rel == "countermeasures" {
			lane = item.Countermeasures
		}
		if lane != nil {
			n += lane.Total
		}
	}
	return n
}
