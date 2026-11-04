// Package uplink is the runtime sensor's client for the vdb-site runtime
// routes (docs/runtime-sensor-api.md there): register with the rules it
// compiled, post rule matches and holds, and long-poll decisions.
//
// It authenticates with the org's ApiKey through pkg/auth, so a sensor holds
// the same credential the CLI does, or with an enrolled device's Sensor
// credential (Authorization). Neither can make a decision: the site refuses
// decisions from both.
package uplink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/addongate"
	"github.com/vulnetix/cli/v4/pkg/auth"
)

// DefaultEndpoint is the site API.
const DefaultEndpoint = "https://www.vulnetix.com/api/site"

// Client talks to /v1/runtime.
type Client struct {
	Endpoint string
	Creds    *auth.Credentials
	// Authorization, when set, is the whole Authorization header and wins
	// over Creds: an enrolled device's "Sensor <deviceUuid>:<secret>".
	Authorization func() string
	HTTP          *http.Client
	Version       string

	stopped atomic.Bool
}

// ErrStopped is returned by every call once Stop was called.
var ErrStopped = errors.New("uplink stopped: the sensor no longer reports")

// Stop makes every later call fail with ErrStopped, for a sensor whose
// credential was revoked: it keeps running offline instead of hammering the
// site with a credential that is refused.
func (c *Client) Stop() { c.stopped.Store(true) }

// Stopped is whether Stop was called.
func (c *Client) Stopped() bool { return c.stopped.Load() }

// AuthHeader is the Authorization header every call sends: the device's
// Sensor credential, else the ApiKey one. Empty with neither.
func (c *Client) AuthHeader() string {
	switch {
	case c.Authorization != nil:
		return c.Authorization()
	case c.Creds != nil:
		return auth.GetAuthHeader(c.Creds)
	}

	return ""
}

// Base is the endpoint calls go to, with the default filled in.
func (c *Client) Base() string {
	if e := strings.TrimRight(c.Endpoint, "/"); e != "" {
		return e
	}

	return DefaultEndpoint
}

// Goodbye says the sensor is stopping, so the console shows a stop rather
// than a silent host. reason is signal, stop, uninstall or upgrade.
func (c *Client) Goodbye(ctx context.Context, sensorKey, reason, detail string) error {
	raw, err := json.Marshal(map[string]string{"sensorKey": sensorKey, "reason": reason, "detail": detail})
	if err != nil {
		return err
	}

	return c.do(ctx, http.MethodPost, "/v1/runtime/sensors/goodbye", raw, nil)
}

// RuleLoad is whether the sensor compiled one rule.
type RuleLoad struct {
	RuleTable string `json:"ruleTable"`
	RuleUUID  string `json:"ruleUuid"`
	Status    string `json:"status"` // compiled | rejected | no-engine
	Reason    string `json:"reason,omitempty"`
	Mode      string `json:"mode"` // block | log
}

// Registration is what the sensor says about itself.
type Registration struct {
	SensorKey     string          `json:"sensorKey"`
	ComputeKind   string          `json:"computeKind"`
	ResourceArn   string          `json:"resourceArn,omitempty"`
	Hostname      string          `json:"hostname"`
	Mode          string          `json:"mode"`
	Version       string          `json:"version"`
	KernelVersion string          `json:"kernelVersion,omitempty"`
	Capabilities  map[string]bool `json:"capabilities"`
	RulesetEtag   string          `json:"rulesetEtag,omitempty"`
	// Metrics is what the sensor costs the host and how its periodic work went.
	Metrics *Metrics `json:"metrics,omitempty"`
	// UpdateState is the outcome of the last self-update the guard recorded
	// ({"state","from","to","reason","at"}); nil when there is none.
	UpdateState json.RawMessage `json:"updateState,omitempty"`
	// RuleLoads nil leaves the server's list as it is; an empty slice says
	// the sensor loads nothing. Encoded by Register.
	RuleLoads []RuleLoad `json:"-"`
}

// Event is one rule match or hold.
type Event struct {
	EventKey      string         `json:"eventKey"`
	RuleTable     string         `json:"ruleTable"`
	RuleUUID      string         `json:"ruleUuid"`
	Lane          string         `json:"lane"`
	SubjectKind   string         `json:"subjectKind"`
	Subject       string         `json:"subject"`
	Action        string         `json:"action"`
	HoldExpiresAt int64          `json:"holdExpiresAt,omitempty"`
	Detail        map[string]any `json:"detail,omitempty"`
	ObservedAt    int64          `json:"observedAt"`
}

// Decision is what a person decided.
type Decision struct {
	UUID        string `json:"uuid"`
	RuleTable   string `json:"ruleTable"`
	RuleUUID    string `json:"ruleUuid"`
	SensorScope string `json:"sensorScope"`
	Subject     string `json:"subject"`
	Verdict     string `json:"verdict"`
	Value       string `json:"value,omitempty"`
	DecidedAt   int64  `json:"decidedAt"`
	Until       int64  `json:"until,omitempty"`
	RevokedAt   int64  `json:"revokedAt,omitempty"`
}

// Register upserts the sensor and returns its server uuid.
func (c *Client) Register(ctx context.Context, r Registration) (string, error) {
	// A pointer, so nil is left out ("unchanged") while an empty slice is sent
	// as [] ("loads nothing"); omitempty on the slice itself would drop both.
	type wire struct {
		Registration
		RuleLoads *[]RuleLoad `json:"ruleLoads,omitempty"`
	}
	w := wire{Registration: r}
	if r.RuleLoads != nil {
		w.RuleLoads = &r.RuleLoads
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	var out struct {
		SensorUUID string `json:"sensorUuid"`
	}
	err = c.do(ctx, http.MethodPost, "/v1/runtime/sensors/register", raw, &out)

	return out.SensorUUID, err
}

// PostEvents sends at most 500 events. It returns how many the server stored
// and the ones it refused, by index and reason.
func (c *Client) PostEvents(ctx context.Context, sensorKey string, events []Event) (int, []string, error) {
	if len(events) > 500 {
		return 0, nil, fmt.Errorf("at most 500 events per post, got %d", len(events))
	}
	raw, err := json.Marshal(map[string]any{"sensorKey": sensorKey, "events": events})
	if err != nil {
		return 0, nil, err
	}
	var out struct {
		Accepted int      `json:"accepted"`
		Rejected []string `json:"rejected"`
	}
	err = c.do(ctx, http.MethodPost, "/v1/runtime/events", raw, &out)

	return out.Accepted, out.Rejected, err
}

// PollDecisions waits up to wait for decisions after since, and returns them
// with the cursor to poll from next.
func (c *Client) PollDecisions(ctx context.Context, sensorKey string, since int64, wait time.Duration) ([]Decision, int64, error) {
	p, err := c.PollDecisionPage(ctx, sensorKey, since, wait)

	return p.Decisions, p.Cursor, err
}

// DecisionPage is one long-poll answer.
type DecisionPage struct {
	Decisions []Decision `json:"decisions"`
	Cursor    int64      `json:"cursor"`
	// ConfigEtag is the etag of the device's profile config, for an
	// enrolled device; empty for a hand-configured sensor. A sensor running
	// another etag pulls its config at once instead of at its next tick.
	ConfigEtag string `json:"configEtag,omitempty"`
}

// PollDecisionPage is PollDecisions with the whole answer. On error the
// cursor is since.
func (c *Client) PollDecisionPage(ctx context.Context, sensorKey string, since int64, wait time.Duration) (DecisionPage, error) {
	q := url.Values{}
	q.Set("sensorKey", sensorKey)
	q.Set("since", strconv.FormatInt(since, 10))
	q.Set("wait", strconv.Itoa(int(wait/time.Second)))
	var out DecisionPage
	if err := c.do(ctx, http.MethodGet, "/v1/runtime/decisions?"+q.Encode(), nil, &out); err != nil {
		return DecisionPage{Cursor: since}, err
	}
	if out.Cursor < since {
		out.Cursor = since
	}

	return out, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	if c.Stopped() {
		return ErrStopped
	}
	endpoint := strings.TrimRight(c.Endpoint, "/")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	var reader io.Reader
	gzipped := false
	if body != nil {
		// Bodies go gzipped: Cloudflare's WAF in front of the site refuses a
		// plain body naming /etc/shadow or carrying an injection string, which
		// is what a sensor reports, and it does not inspect a compressed one.
		if z, err := gzipBytes(body); err == nil {
			reader, gzipped = bytes.NewReader(z), true
		} else {
			reader = bytes.NewReader(body)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if gzipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Header.Set("User-Agent", "vulnetix-sensor/"+c.Version)
	switch {
	case c.Authorization != nil:
		if h := c.Authorization(); h != "" {
			req.Header.Set("Authorization", h)
		}
	case c.Creds != nil:
		if h := auth.GetAuthHeader(c.Creds); h != "" {
			req.Header.Set("Authorization", h)
		}
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	// A missing add-on is a denial, whether the site said 402 or the soft 200
	// marker. It must never be read as an answer: a 200 planLocked parsed as
	// success makes PostEvents report the batch sent and the caller drop it.
	if denied := addongate.FromResponse(method, req.URL.Path, resp.StatusCode, data); denied != nil {
		return denied
	}
	if out == nil && resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, e.Error)
		}

		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}

	return json.Unmarshal(data, out)
}

// InventoryPackage is one package running processes map.
type InventoryPackage struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	State     string   `json:"state"`
	Processes int      `json:"processes"`
	Examples  []string `json:"examples,omitempty"`
	// Purl is the package URL carrying the host's real distro, architecture
	// and source package, which is what a distro advisory matches on.
	Purl string `json:"purl,omitempty"`
	// Arch is the package's architecture: a host may carry one package for
	// two (libc6 for amd64 and i386).
	Arch string `json:"arch,omitempty"`
	// Files are up to 5 of the package's files a running process has mapped
	// (its shared libraries, not only the executable): where a flaw in it is
	// loaded.
	Files []string `json:"files,omitempty"`
}

// InventoryReport is one inventory post. Complete, Warnings and Unsupported say
// how much of the host it describes: the site replaces the stored list with a
// report only when it can trust it to be the whole host.
type InventoryReport struct {
	Packages []InventoryPackage
	// Complete is nil when the sensor cannot say (the site then guards on the
	// counts), true when every package database present was read, and false
	// when one could not be.
	Complete *bool
	// Warnings name the databases that could not be read.
	Warnings []string
	// Unsupported is why this host's packages cannot be read at all.
	Unsupported string
	// Seq orders this sensor's reports: the time the host was read, in ms. The
	// site does not apply a report older than the last it applied.
	Seq int64
}

// PostInventory replaces the sensor's in-use package report.
func (c *Client) PostInventory(ctx context.Context, sensorKey string, packages []InventoryPackage) (int, error) {
	return c.PostInventoryReport(ctx, sensorKey, InventoryReport{Packages: packages})
}

// PostInventoryReport replaces the sensor's package report and says how
// complete it is.
func (c *Client) PostInventoryReport(ctx context.Context, sensorKey string, r InventoryReport) (int, error) {
	packages := r.Packages
	if packages == nil {
		packages = []InventoryPackage{}
	}
	body := map[string]any{"sensorKey": sensorKey, "packages": packages}
	if r.Complete != nil {
		body["complete"] = *r.Complete
	}
	if len(r.Warnings) > 0 {
		body["warnings"] = r.Warnings
	}
	if r.Unsupported != "" {
		body["unsupported"] = r.Unsupported
	}
	if r.Seq > 0 {
		body["seq"] = r.Seq
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	var out struct {
		Stored int `json:"stored"`
	}
	err = c.do(ctx, http.MethodPost, "/v1/runtime/inventory", raw, &out)

	return out.Stored, err
}

// Metrics is the sensor's own footprint and the state of its periodic work,
// sent with every heartbeat.
type Metrics struct {
	StartedAt  int64               `json:"startedAt"`
	UptimeSec  int64               `json:"uptimeSec"`
	CPUSec     float64             `json:"cpuSec"`
	RSSBytes   uint64              `json:"rssBytes"`
	HeapBytes  uint64              `json:"heapBytes"`
	SysBytes   uint64              `json:"sysBytes"`
	Goroutines int                 `json:"goroutines"`
	NumGC      uint32              `json:"numGc"`
	Passes     map[string]PassStat `json:"passes"`
}

// PassStat is how one kind of periodic work (inventory, feeds, config,
// hostchecks, flush) last went.
type PassStat struct {
	LastAt     int64  `json:"lastAt"`
	DurationMs int64  `json:"durationMs"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Runs       int    `json:"runs"`
	Failures   int    `json:"failures"`
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
