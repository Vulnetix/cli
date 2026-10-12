package cmd

// `tea products` and `tea components`: list, filter and search a catalogue.
//
// The server can do exactly two things with a list: page it and filter it on one
// identifier, matched exactly. It has no name search. A `--search` therefore
// works client side, paging through the catalogue and keeping what matches, and
// it is capped so that a stray query against a large catalogue cannot turn into
// an unbounded crawl. The exact filters (--purl, --tei, --id-type/--id-value)
// are the efficient route and the search says so when the cap stops it.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

const (
	// teaMaxPages bounds every multi-page walk (--search, --all, a large --limit).
	teaMaxPages = 20
	// teaMaxPageSize is the largest pageSize the server accepts.
	teaMaxPageSize = 100
	// teaDefaultLimit is how many rows are printed when --limit is not given.
	teaDefaultLimit = 50
)

// teaListFlags are the validated list flags.
type teaListFlags struct {
	Search    string
	PageToken string
	All       bool
	Limit     int
	LimitSet  bool
	// Filter is the server side identifier filter, zero when none was asked for.
	Filter tea.ListOptions
}

// teaListResult is what a (possibly multi-page) walk collected.
type teaListResult[T any] struct {
	Results       []T
	HasNext       bool
	NextPageToken string
	// Scanned is how many items were read from the server, matching or not.
	Scanned int
	// CapHit is true when the page cap stopped a walk that had more to read.
	CapHit bool
	// LimitHit is true when --limit stopped a walk that had more to give.
	LimitHit bool
}

func addTeaListFlags(cmd *cobra.Command, noun string) {
	f := cmd.Flags()
	f.String("search", "", "case-insensitive text to find in the "+noun+" name or any identifier (client side; reads at most 20 pages of 100)")
	f.String("purl", "", "exact PURL filter, for example pkg:github/prefix-dev/pixi (server side)")
	f.String("tei", "", "exact TEI filter, for example urn:tei:uuid:vulnetix.com:<uuid> (server side)")
	f.String("id-type", "", "identifier type for an exact filter: "+strings.Join(tea.IDTypes, ", ")+" (use with --id-value)")
	f.String("id-value", "", "identifier value for an exact filter (use with --id-type)")
	f.Int("limit", teaDefaultLimit, "most "+noun+"s to print")
	f.String("page-token", "", "continue from the token an earlier call printed")
	f.Bool("all", false, "follow every page, up to 20 pages of 100 (no row limit unless --limit is given)")
}

// teaReadListFlags validates the list flags. Every error names the flags
// involved, because the combinations that are refused are the ones that would
// otherwise be silently ignored in favour of one of them.
func teaReadListFlags(cmd *cobra.Command) (*teaListFlags, error) {
	fl := cmd.Flags()
	str := func(name string) string { v, _ := fl.GetString(name); return strings.TrimSpace(v) }

	out := &teaListFlags{
		Search:    str("search"),
		PageToken: str("page-token"),
		LimitSet:  fl.Changed("limit"),
	}
	out.All, _ = fl.GetBool("all")
	out.Limit, _ = fl.GetInt("limit")

	purl, tei, idType, idValue := str("purl"), str("tei"), str("id-type"), str("id-value")
	for _, name := range []string{"search", "purl", "tei", "id-type", "id-value", "page-token"} {
		if fl.Changed(name) && str(name) == "" {
			return nil, fmt.Errorf("--%s needs a value", name)
		}
	}
	if out.Limit < 1 {
		return nil, fmt.Errorf("--limit must be at least 1")
	}
	if (idType == "") != (idValue == "") {
		return nil, fmt.Errorf("--id-type and --id-value must be given together")
	}

	var used []string
	if out.Search != "" {
		used = append(used, "--search")
	}
	if purl != "" {
		used = append(used, "--purl")
	}
	if tei != "" {
		used = append(used, "--tei")
	}
	if idType != "" {
		used = append(used, "--id-type/--id-value")
	}
	if len(used) > 1 {
		return nil, fmt.Errorf("%s cannot be combined: use one of them", strings.Join(used, " and "))
	}

	switch {
	case purl != "":
		out.Filter.IDType, out.Filter.IDValue = "PURL", purl
	case tei != "":
		out.Filter.IDType, out.Filter.IDValue = "TEI", tei
	case idType != "":
		t, ok := tea.ValidIDType(idType)
		if !ok {
			return nil, fmt.Errorf("--id-type %q is not one of %s", idType, strings.Join(tea.IDTypes, ", "))
		}
		out.Filter.IDType, out.Filter.IDValue = t, idValue
	}
	return out, nil
}

// teaCollect reads pages through fetch until the request is satisfied.
//
// One mechanism serves every mode: a plain call reads as many pages as --limit
// needs, --all keeps going, and a search keeps only what match. All of them stop
// at teaMaxPages and report that they did, so the caller can tell a catalogue
// that ran out from a walk that was cut off.
func teaCollect[T any](
	ctx context.Context,
	fetch func(context.Context, tea.ListOptions) (*tea.Page[T], error),
	f *teaListFlags,
	match func(T) bool,
) (*teaListResult[T], error) {
	limit := f.Limit
	if f.All && !f.LimitSet {
		limit = 0 // no cap on rows; the page cap still applies
	}
	wide := f.All || match != nil

	res := &teaListResult[T]{Results: []T{}}
	opts := f.Filter
	opts.PageToken = f.PageToken

	for page := 1; ; page++ {
		opts.PageSize = teaMaxPageSize
		if !wide && limit-len(res.Results) < teaMaxPageSize {
			opts.PageSize = limit - len(res.Results)
		}
		p, err := fetch(ctx, opts)
		if err != nil {
			return nil, err
		}
		res.Scanned += len(p.Results)
		res.HasNext = p.HasNext && p.NextPageToken != ""
		res.NextPageToken = p.NextPageToken

		for _, it := range p.Results {
			if match != nil && !match(it) {
				continue
			}
			if limit > 0 && len(res.Results) >= limit {
				// Items remain beyond the row limit that this walk will not
				// report, so a token for the next page would skip them.
				res.LimitHit, res.HasNext, res.NextPageToken = true, false, ""
				return res, nil
			}
			res.Results = append(res.Results, it)
		}

		if !res.HasNext {
			res.NextPageToken = ""
			return res, nil
		}
		if limit > 0 && len(res.Results) >= limit {
			// The limit is met exactly on this page boundary. A search cannot
			// know whether more matches follow, so it stops here too.
			if match != nil {
				res.LimitHit, res.HasNext, res.NextPageToken = true, false, ""
			}
			return res, nil
		}
		if page >= teaMaxPages {
			res.CapHit = true
			return res, nil
		}
		opts.PageToken = p.NextPageToken
	}
}

// teaSearchMatcher builds the client side predicate for --search: a
// case-insensitive substring over the name and every identifier value.
func teaSearchMatcher(text string) func(name string, ids []tea.Identifier) bool {
	needle := strings.ToLower(text)
	return func(name string, ids []tea.Identifier) bool {
		if strings.Contains(strings.ToLower(name), needle) {
			return true
		}
		for _, id := range ids {
			if strings.Contains(strings.ToLower(id.IDValue), needle) {
				return true
			}
		}
		return false
	}
}

// newTeaListCommand builds `products` or `components`: the two differ only in
// the endpoint and the noun, so one constructor keeps their flags and output
// identical by construction.
func newTeaListCommand[T any](
	use, short, long, noun string,
	fetch func(*tea.Client) func(context.Context, tea.ListOptions) (*tea.Page[T], error),
	view func(T) (uuid, name string, ids []tea.Identifier),
) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := teaReadListFlags(cmd)
			if err != nil {
				return err
			}
			c, err := teaReadClient(cmd)
			if err != nil {
				return err
			}
			ctx, cancel := teaContext(cmd)
			defer cancel()

			var match func(T) bool
			if f.Search != "" {
				m := teaSearchMatcher(f.Search)
				match = func(it T) bool {
					_, name, ids := view(it)
					return m(name, ids)
				}
			}
			res, err := teaCollect(ctx, fetch(c), f, match)
			if err != nil {
				return teaFailFor(cmd, err)
			}

			switch {
			case f.Search != "" && res.CapHit:
				fmt.Fprintf(os.Stderr, "searched the first %d items; use --purl or --tei for an exact match\n", res.Scanned)
			case f.Search != "" && res.LimitHit:
				fmt.Fprintf(os.Stderr, "showing the first %d matches (--limit); raise --limit to see more\n", len(res.Results))
			case res.CapHit:
				fmt.Fprintf(os.Stderr, "stopped after %d pages (%d items); continue with --page-token %s\n",
					teaMaxPages, res.Scanned, res.NextPageToken)
			case res.LimitHit:
				fmt.Fprintf(os.Stderr, "showing the first %d %ss (--limit); raise --limit to see more\n", len(res.Results), noun)
			}

			if teaJSONFlag(cmd) {
				return teaPrintJSON(tea.Page[T]{
					Results:       res.Results,
					HasNext:       res.HasNext,
					NextPageToken: res.NextPageToken,
				})
			}
			for _, it := range res.Results {
				uuid, name, _ := view(it)
				fmt.Printf("%s  %s\n", uuid, name)
			}
			if len(res.Results) == 0 && f.Search != "" {
				fmt.Fprintf(os.Stderr, "no %ss matched %q\n", noun, f.Search)
			}
			if res.HasNext && !f.All {
				fmt.Printf("\nmore available; continue with --page-token %s\n", res.NextPageToken)
			}
			return nil
		},
	}
	addTeaListFlags(cmd, noun)
	return cmd
}

func newTeaProductsCommand() *cobra.Command {
	return newTeaListCommand(
		"products",
		"List or search the products a TEA server publishes",
		`List the products a TEA server publishes, one per line: the product UUID
and its name.

Find one product by an exact identifier with --purl, --tei or --id-type with
--id-value. The server matches these exactly, with no wildcards and no case
folding, and they are the fast route. --search matches text instead: it reads
up to 20 pages of 100 from the server and keeps the items whose name or any
identifier contains the text, ignoring case.

Page with --limit (rows printed, default 50), --page-token (continue where an
earlier call stopped) and --all (follow every page, up to 20).

Examples:
  vulnetix tea products
  vulnetix tea --catalogue public products --search pixi
  vulnetix tea --catalogue public products --purl pkg:github/prefix-dev/pixi
  vulnetix tea --catalogue public products --all --json`,
		"product",
		func(c *tea.Client) func(context.Context, tea.ListOptions) (*tea.Page[tea.Product], error) {
			return c.ListProducts
		},
		func(p tea.Product) (string, string, []tea.Identifier) { return p.UUID, p.Name, p.Identifiers },
	)
}

func newTeaComponentsCommand() *cobra.Command {
	return newTeaListCommand(
		"components",
		"List or search the components a TEA server publishes",
		`List the components a TEA server publishes, one per line: the component
UUID and its name. Takes the same flags as products and behaves the same way.

Examples:
  vulnetix tea --catalogue public components --search pixi
  vulnetix tea --catalogue public components --purl pkg:github/prefix-dev/pixi
  vulnetix tea components --id-type TEI --id-value urn:tei:uuid:vulnetix.com:<uuid>`,
		"component",
		func(c *tea.Client) func(context.Context, tea.ListOptions) (*tea.Page[tea.Component], error) {
			return c.ListComponents
		},
		func(p tea.Component) (string, string, []tea.Identifier) { return p.UUID, p.Name, p.Identifiers },
	)
}
