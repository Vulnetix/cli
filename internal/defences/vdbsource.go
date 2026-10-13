package defences

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// API is the part of the vulnerability database client the source uses. It is an
// interface so the source can be tested with a fake that answers as the API does.
type API interface {
	// V2DefenceCounts is POST /v2/defences/counts: counts for every plan, the
	// defences with their console links for Pro. It chunks by 100 items.
	V2DefenceCounts(items []vdb.DefenceCountsItem) (*vdb.DefenceCountsResponse, error)
	// V2VulnDefences is GET /v2/vuln/{id}/{lane}: the full records, Pro only.
	V2VulnDefences(lane, identifier string) (map[string]interface{}, error)
	// V2DefenceArchive is GET /v2/{lane}/{uuid}/archive: one rule body, Pro only.
	V2DefenceArchive(lane, uuid string) ([]byte, error)
}

var (
	factoryMu sync.RWMutex
	factory   func() API
)

// SetClientFactory registers how the default source gets its client. It is a
// factory, not a client, because credentials are resolved after packages
// initialise: the source asks for one when it is first used.
func SetClientFactory(f func() API) {
	factoryMu.Lock()
	factory = f
	factoryMu.Unlock()
}

func newAPI() API {
	factoryMu.RLock()
	defer factoryMu.RUnlock()
	if factory == nil {
		return nil
	}
	return factory()
}

// vdbSource talks to the vulnerability database.
//
// A scan asks for counts: one POST for every no-fix advisory, whatever the plan.
// Detail (rule bodies' metadata, coverage notes, checksums) comes from the
// per-vulnerability endpoints and is requested only by `defend`, because it is
// one request per lane per advisory and a scan does not need it.
type vdbSource struct {
	// api overrides the registered client, for tests.
	api API
	// offline makes the source behave as a build with no client at all.
	offline bool
}

// Unavailable is a Source that cannot ask: every lookup is StateUnavailable. It is
// what a test uses to be certain it never reaches the network.
var Unavailable Source = &vdbSource{offline: true}

// NewVDBSource returns a Source backed by api.
func NewVDBSource(api API) Source { return &vdbSource{api: api} }

func (s *vdbSource) client() API {
	if s.offline {
		return nil
	}
	if s.api != nil {
		return s.api
	}
	return newAPI()
}

// laneRel is the API path segment for a lane.
func laneRel(l Lane) string {
	if l == LaneBlock {
		return "virtual-patches"
	}
	return "countermeasures"
}

func (s *vdbSource) Lookup(ctx context.Context, ids []string, opts LookupOptions) (map[string]Summary, error) {
	api := s.client()
	out := make(map[string]Summary, len(ids))
	if api == nil {
		// No client registered: this build cannot ask. Say nothing rather than
		// "none": reporting StateNone would claim a lookup that never happened.
		for _, id := range ids {
			out[id] = Summary{ID: id, State: StateUnavailable, Reason: ErrNotAvailable.Error()}
		}
		return out, nil
	}
	if len(ids) == 0 {
		return out, nil
	}

	items := make([]vdb.DefenceCountsItem, 0, len(ids))
	for _, id := range ids {
		var it vdb.DefenceCountsItem
		it.Key = id
		it.VulnIDs = []string{id}
		items = append(items, it)
	}
	// The client call takes no context, so it runs in its own goroutine and the
	// caller's deadline decides how long a scan waits. A slow lookup costs the
	// defence lines, never the scan.
	type answer struct {
		resp *vdb.DefenceCountsResponse
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		r, e := api.V2DefenceCounts(items)
		done <- answer{r, e}
	}()
	var resp *vdb.DefenceCountsResponse
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("timed out: %w", ctx.Err())
	case a := <-done:
		if a.err != nil {
			return nil, a.err
		}
		resp = a.resp
	}

	byKey := make(map[string]vdb.DefenceCountsResult, len(resp.Items))
	for i, it := range resp.Items {
		key := it.Key
		if key == "" && i < len(ids) {
			key = ids[i] // items come back in request order
		}
		byKey[key] = it
	}
	for _, id := range ids {
		it, ok := byKey[id]
		if !ok {
			out[id] = Summary{ID: id, State: StateFailed, Reason: "no answer for this identifier"}
			continue
		}
		out[id] = summaryFromCounts(id, it)
	}

	// Detail only where there is something to detail, and only when asked.
	if opts.Detail && opts.Pro {
		for id, sum := range out {
			if sum.Total() == 0 || sum.State == StateFailed {
				continue
			}
			if detailed, derr := s.detail(api, id, sum); derr == nil {
				out[id] = detailed
			}
		}
	}
	return out, nil
}

// summaryFromCounts maps one counts item onto a Summary.
func summaryFromCounts(id string, it vdb.DefenceCountsResult) Summary {
	sum := Summary{ID: id}
	if it.Error != nil {
		sum.State = StateFailed
		sum.Reason = it.Error.Message
		if it.Error.Status >= 400 && it.Error.Status < 500 && it.Error.Field != "" {
			// The identifier was refused as input: it is not one defences are keyed to.
			sum.State = StateNotIndexed
		}
		return sum
	}
	fill := func(dst *LaneSummary, src *vdb.DefenceLaneCounts) {
		dst.ByKind = map[Kind]int{}
		if src == nil {
			return
		}
		dst.Count = src.Total
		for k, n := range src.ByKind {
			dst.ByKind[Kind(strings.ToUpper(k))] = n
		}
		for _, d := range src.Defences {
			dst.Rules = append(dst.Rules, Rule{
				UUID: d.UUID, Kind: Kind(strings.ToUpper(d.Kind)), Title: d.Title,
				Confidence: d.Confidence, DeployMode: d.DeployMode, FalsePositiveRisk: d.FalsePositiveRisk,
				ConsoleURL: d.ConsoleURL, ArchiveURL: "/v2/" + laneRel(laneOfKind(d.Kind)) + "/" + d.UUID + "/archive",
			})
		}
	}
	fill(&sum.Block, it.VirtualPatches)
	fill(&sum.Detect, it.Countermeasures)
	sum.Classify()
	return sum
}

func laneOfKind(k string) Lane { return LaneOf(Kind(strings.ToUpper(k))) }

// detail replaces a summary's rules with the full records, which carry coverage
// notes, the exploit each was built from, and the body checksum. Counts stay as
// the counts endpoint reported them.
func (s *vdbSource) detail(api API, id string, sum Summary) (Summary, error) {
	for _, lane := range []Lane{LaneBlock, LaneDetect} {
		ls := &sum.Block
		if lane == LaneDetect {
			ls = &sum.Detect
		}
		if ls.Count == 0 {
			continue
		}
		raw, err := api.V2VulnDefences(laneRel(lane), id)
		if err != nil {
			return sum, err
		}
		recs, _ := raw[laneRel(lane)].([]interface{})
		if len(recs) == 0 {
			continue
		}
		var rules []Rule
		for _, r := range recs {
			m, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			rules = append(rules, ruleFromRecord(m, lane))
		}
		if len(rules) > 0 {
			ls.Rules = mergeRules(ls.Rules, rules)
		}
	}
	return sum, nil
}

// ruleFromRecord reads one full defence record.
func ruleFromRecord(m map[string]interface{}, lane Lane) Rule {
	str := func(k string) string { s, _ := m[k].(string); return s }
	r := Rule{
		UUID: str("uuid"), ArtifactID: str("artifactId"), Kind: Kind(strings.ToUpper(str("kind"))),
		Title: str("title"), Confidence: str("confidence"), DeployMode: str("deployMode"),
		FalsePositiveRisk: str("falsePositiveRisk"), CoverageNotes: str("coverageNotes"),
		ExploitID: str("exploitId"), ExploitSource: str("exploitSource"), ExploitURL: str("exploitUrl"),
		SHA256: str("bodyContentHash"), ArchiveURL: str("archiveUrl"),
	}
	if ts, ok := m["mitreTechIds"].([]interface{}); ok {
		for _, t := range ts {
			if s, ok := t.(string); ok {
				r.MitreTechIDs = append(r.MitreTechIDs, s)
			}
		}
	}
	if r.ArchiveURL == "" && r.UUID != "" {
		r.ArchiveURL = "/v2/" + laneRel(lane) + "/" + r.UUID + "/archive"
	}
	return r
}

// mergeRules lets the detailed record win while keeping what only the counts
// endpoint carries (the console link), and keeps rules the detail page omitted.
func mergeRules(brief, detail []Rule) []Rule {
	byUUID := map[string]Rule{}
	for _, b := range brief {
		byUUID[b.UUID] = b
	}
	seen := map[string]bool{}
	var out []Rule
	for _, d := range detail {
		if b, ok := byUUID[d.UUID]; ok {
			if d.ConsoleURL == "" {
				d.ConsoleURL = b.ConsoleURL
			}
		}
		seen[d.UUID] = true
		out = append(out, d)
	}
	for _, b := range brief {
		if !seen[b.UUID] {
			out = append(out, b)
		}
	}
	return out
}

func (s *vdbSource) Download(_ context.Context, rule Rule) (Body, error) {
	api := s.client()
	if api == nil {
		return Body{}, ErrNotAvailable
	}
	if rule.UUID == "" {
		return Body{}, errors.New("rule has no identifier to download")
	}
	content, err := api.V2DefenceArchive(laneRel(LaneOf(rule.Kind)), rule.UUID)
	if err != nil {
		var locked *vdb.PlanLockedError
		if errors.As(err, &locked) {
			return Body{}, fmt.Errorf("rule downloads need a Pro plan: %w", err)
		}
		return Body{}, err
	}
	id := rule.ArtifactID
	if id == "" {
		id = rule.UUID
	}
	return Body{
		Kind: rule.Kind, FileName: FileName(id, rule.Kind), Content: content, SHA256: rule.SHA256,
	}, nil
}
