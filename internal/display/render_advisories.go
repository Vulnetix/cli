package display

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// maxAdvisoryRows caps each section of the advisories view. Log4Shell alone has
// 284 vendor patches and 20 references; the full set is what -o json is for.
const maxAdvisoryRows = 6

// RenderAdvisories renders the advisories for one vulnerability.
//
// The v2 response is not a list of advisories. It is a record with one section
// per kind of source: Red Hat errata, vendor patches, MSRC patches, solutions,
// vendor comments, references and an AI advisory. This renderer used to look for
// an "advisories" array that the API has never returned, so it printed "No
// advisories found" for every vulnerability, including ones with hundreds of
// vendor patches. The array is still honoured for any caller that supplies one.
func RenderAdvisories(data any, ctx *Context) string {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Sprintf("%v", data)
	}
	t := ctx.Term
	var b strings.Builder

	id := ToStringVal(m["identifier"])
	head := Bold(t, "Advisories for "+id)
	if st := ToStringVal(m["state"]); st != "" {
		head += "  " + Muted(t, st)
	}
	b.WriteString("\n" + head + "\n")
	if title := ToStringVal(m["title"]); title != "" {
		b.WriteString(Muted(t, "  "+Truncate(title, t.Width-4)) + "\n")
	}

	shown := 0
	section := func(title string, count int, body func()) {
		if count == 0 {
			return
		}
		shown++
		b.WriteString("\n" + Subheader(t, title) + Muted(t, fmt.Sprintf("  %d", count)) + "\n")
		body()
	}
	more := func(total, shownRows int) {
		if total > shownRows {
			b.WriteString(Muted(t, fmt.Sprintf("  … and %d more (-o json for all)", total-shownRows)) + "\n")
		}
	}

	// A flat advisories array, when a caller supplies one.
	if list := asMapSlice(m["advisories"]); len(list) > 0 {
		section("Advisories", len(list), func() {
			for _, am := range firstN(list, maxAdvisoryRows) {
				name := firstString(am, "id", "advisoryId", "title")
				u := ToStringVal(am["url"])
				src := ToStringVal(am["source"])
				// Reference rows from the batched endpoint have a URL and a source
				// and no id: the URL is the thing to show.
				if name == "" {
					name, u = u, ""
				}
				line := "  " + Bold(t, name)
				if src != "" {
					line += "  " + Muted(t, "["+src+"]")
				}
				b.WriteString(line + "\n")
				if u != "" {
					b.WriteString("    " + Muted(t, u) + "\n")
				}
			}
			more(len(list), maxAdvisoryRows)
		})
	}

	// Red Hat errata: newest first, with the errata id read from its URL.
	rh := asMapSlice(m["redhatAdvisories"])
	sort.SliceStable(rh, func(i, j int) bool { return unixOf(rh[i]["initialReleaseDate"]) > unixOf(rh[j]["initialReleaseDate"]) })
	section("Red Hat advisories", len(rh), func() {
		for _, a := range firstN(rh, maxAdvisoryRows) {
			url := ToStringVal(a["errataUrl"])
			line := "  " + Bold(t, errataID(url))
			var meta []string
			if d := dateOf(a["initialReleaseDate"]); d != "" {
				meta = append(meta, "released "+d)
			}
			if d := dateOf(a["currentReleaseDate"]); d != "" && d != dateOf(a["initialReleaseDate"]) {
				meta = append(meta, "updated "+d)
			}
			if n := len(asMapSlice(a["products"])); n > 0 {
				meta = append(meta, fmt.Sprintf("%d %s", n, map[bool]string{true: "product", false: "products"}[n == 1]))
			}
			if len(meta) > 0 {
				line += "  " + Muted(t, strings.Join(meta, " · "))
			}
			b.WriteString(line + "\n")
			if url != "" {
				b.WriteString("    " + Muted(t, url) + "\n")
			}
		}
		more(len(rh), maxAdvisoryRows)
	})

	for _, s := range []struct{ key, title string }{
		{"msrcPatches", "Microsoft (MSRC) patches"},
		{"solutions", "Solutions"},
		{"vendorComments", "Vendor comments"},
	} {
		list := asMapSlice(m[s.key])
		section(s.title, len(list), func() {
			for _, item := range firstN(list, maxAdvisoryRows) {
				b.WriteString("  " + Truncate(describeItem(item), t.Width-4) + "\n")
			}
			more(len(list), maxAdvisoryRows)
		})
	}

	// Vendor patches are numerous and terse (product, vendor, source), so they
	// are summarised by vendor rather than listed.
	patches := asMapSlice(m["vendorPatches"])
	section("Vendor patches", len(patches), func() {
		byVendor := map[string]int{}
		for _, p := range patches {
			v := firstString(p, "vendor", "source")
			if v == "" {
				v = "unknown"
			}
			byVendor[v]++
		}
		type vc struct {
			v string
			n int
		}
		var vs []vc
		for v, n := range byVendor {
			vs = append(vs, vc{v, n})
		}
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].n != vs[j].n {
				return vs[i].n > vs[j].n
			}
			return vs[i].v < vs[j].v
		})
		var parts []string
		for _, x := range firstN2(vs, 8) {
			parts = append(parts, fmt.Sprintf("%s (%d)", x.v, x.n))
		}
		b.WriteString("  " + strings.ReplaceAll(wordWrap(strings.Join(parts, ", "), t.Width-4), "\n", "\n  ") + "\n")
		if len(vs) > 8 {
			b.WriteString(Muted(t, fmt.Sprintf("  … and %d more vendors (-o json for all)", len(vs)-8)) + "\n")
		}
	})

	refs := asMapSlice(m["references"])
	section("References", len(refs), func() {
		for _, r := range firstN(refs, maxAdvisoryRows) {
			line := "  " + ToStringVal(r["url"])
			if src := ToStringVal(r["source"]); src != "" {
				line += "  " + Muted(t, "["+src+"]")
			}
			b.WriteString(line + "\n")
		}
		more(len(refs), maxAdvisoryRows)
	})

	if ai, ok := m["aiAdvisory"].(map[string]any); ok && len(ai) > 0 {
		shown++
		b.WriteString("\n" + Subheader(t, "AI advisory") + "\n")
		for _, k := range []string{"summary", "description", "recommendation", "impact", "text"} {
			if s := ToStringVal(ai[k]); s != "" {
				b.WriteString("  " + wordWrap(s, t.Width-4) + "\n")
			}
		}
	}

	if shown == 0 {
		b.WriteString("\n" + Muted(t, "  No advisories were returned for "+id+".") + "\n")
		b.WriteString(Muted(t, "  The database returned nothing for it; that is not proof none exist. Check the sources directly:") + "\n")
		b.WriteString(Muted(t, "  https://osv.dev/vulnerability/"+id) + "\n")
	}
	return b.String()
}

func asMapSlice(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func firstN(in []map[string]any, n int) []map[string]any {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func firstN2[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := ToStringVal(m[k]); s != "" {
			return s
		}
	}
	return ""
}

// describeItem renders an item of an unmodelled section from whichever of the
// usual fields it carries.
func describeItem(m map[string]any) string {
	var parts []string
	for _, k := range []string{"id", "kb", "title", "name", "description", "url"} {
		if s := ToStringVal(m[k]); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%v", m)
	}
	return strings.Join(parts, "  ")
}

// unixOf reads a timestamp that may be seconds or milliseconds.
func unixOf(v any) int64 {
	f := ToFloat64(v)
	if f <= 0 {
		return 0
	}
	if f > 1e12 {
		f /= 1000
	}
	return int64(f)
}

// dateOf formats a timestamp as a date, or "" when it is unset or implausible.
// The API returns 0 and negative sentinels for "unknown", which would otherwise
// print as 1970 or year 1.
func dateOf(v any) string {
	u := unixOf(v)
	if u <= 0 {
		return ""
	}
	d := time.Unix(u, 0).UTC()
	if d.Year() < 1990 {
		return ""
	}
	return d.Format("2006-01-02")
}

// errataID turns a Red Hat CSAF URL into the identifier people recognise:
// .../rhsa-2025_1747.json becomes RHSA-2025:1747.
func errataID(url string) string {
	if url == "" {
		return "advisory"
	}
	base := url[strings.LastIndex(url, "/")+1:]
	base = strings.TrimSuffix(base, ".json")
	if i := strings.Index(base, "_"); i > 0 {
		return strings.ToUpper(base[:i]) + ":" + base[i+1:]
	}
	return strings.ToUpper(base)
}
