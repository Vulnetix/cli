package engine

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
)

// The ModSecurity engine, on Coraza.
//
// Each feed rule is one or more SecRule directives with an id action. Coraza
// reports matches by that id, so the engine keeps id -> feed rule, and refuses
// a rule whose ids collide with another's: two rules sharing an id would make
// every match ambiguous.
//
// Rules are compiled together, and then one by one only when the batch fails,
// so a single bad rule costs its own load rather than the whole set.

type modsecEngine struct {
	waf  coraza.WAF
	byID map[int]decide.RuleRef
}

var secRuleID = regexp.MustCompile(`(?:^|[",\s])id\s*:\s*'?(\d+)`)

// detectionOnly runs the engine without letting Coraza interrupt anything;
// the verdict engine decides.
const detectionOnly = "SecRuleEngine DetectionOnly\nSecRequestBodyAccess On\nSecRequestBodyLimit 1048576\n"

func compileModSecurity(rules []feed.Rule) (*modsecEngine, []Result) {
	if len(rules) == 0 {
		return nil, nil
	}

	results := make([]Result, 0, len(rules))
	byID := map[int]decide.RuleRef{}
	var accepted []feed.Rule
	for _, r := range rules {
		ids := ruleIDs(r.Body)
		if len(ids) == 0 {
			results = append(results, Result{Rule: r, Status: Rejected, Reason: "no SecRule id, so a match could not be attributed"})

			continue
		}
		clash := ""
		for _, id := range ids {
			if other, taken := byID[id]; taken && other != ref(r) {
				clash = fmt.Sprintf("rule id %d is also used by %s", id, other.UUID)
			}
		}
		if clash != "" {
			results = append(results, Result{Rule: r, Status: Rejected, Reason: clash})

			continue
		}
		if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(detectionOnly + r.Body)); err != nil {
			results = append(results, Result{Rule: r, Status: Rejected, Reason: firstLine(err.Error())})

			continue
		}
		for _, id := range ids {
			byID[id] = ref(r)
		}
		accepted = append(accepted, r)
	}
	if len(accepted) == 0 {
		return nil, results
	}

	var directives strings.Builder
	directives.WriteString(detectionOnly)
	for _, r := range accepted {
		directives.WriteString(r.Body)
		directives.WriteString("\n")
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives.String()))
	if err != nil {
		// Each compiled alone and not together: an interaction between
		// rules. Report it on all of them rather than guess which.
		for _, r := range accepted {
			results = append(results, Result{Rule: r, Status: Rejected, Reason: "conflicts with another rule in the set: " + firstLine(err.Error())})
		}

		return nil, results
	}
	for _, r := range accepted {
		results = append(results, Result{Rule: r, Status: Compiled})
	}

	return &modsecEngine{waf: waf, byID: byID}, results
}

func (m *modsecEngine) inspect(r *http.Request, body []byte) []Hit {
	tx := m.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	clientHost, clientPort := splitHostPort(r.RemoteAddr)
	serverHost, serverPort := splitHostPort(r.Host)
	tx.ProcessConnection(clientHost, clientPort, serverHost, serverPort)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
	tx.ProcessRequestHeaders()
	if len(body) > 0 {
		_, _, _ = tx.WriteRequestBody(body)
	}
	_, _ = tx.ProcessRequestBody()

	var hits []Hit
	for _, matched := range tx.MatchedRules() {
		id := matched.Rule().ID()
		rr, ok := m.byID[id]
		if !ok {
			continue
		}
		detail := matched.Message()
		if detail == "" {
			detail = "SecRule " + strconv.Itoa(id) + " matched"
		}
		hits = append(hits, Hit{Rule: rr, Detail: detail})
	}

	return hits
}

func ruleIDs(body string) []int {
	seen := map[int]bool{}
	var ids []int
	for _, m := range secRuleID.FindAllStringSubmatch(body, -1) {
		id, err := strconv.Atoi(m[1])
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Ints(ids)

	return ids
}

func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(port)

	return host, p
}

func firstLine(s string) string {
	if i := bytes.IndexByte([]byte(s), '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 280 {
		s = s[:280]
	}

	return s
}
