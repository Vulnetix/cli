// Command vulnetix-sensor is the Vulnetix runtime sensor.
//
// It sits in a workload's path, applies the organisation's virtual patches
// and countermeasures from its published detection rule feeds, and reports to
// the console's Runtime page, where a person decides about anything it holds.
//
// A separate binary from vulnetix so the CLI does not carry the rule engines,
// and so a sidecar or Lambda layer carries only this.
//
//	vulnetix-sensor --mode guard \
//	  --listen :8080 --upstream http://127.0.0.1:8081 --health-path /healthz \
//	  --egress-listen 127.0.0.1:3128 \
//	  --feed https://vulnetix.com/feeds/<org>/<feed> --feed-key <base64 Ed25519 public key>
//
// Where there is no eBPF (Fargate), the sensor can start the workload itself
// and refuse its execs before they run:
//
//	vulnetix-sensor run --mode guard --feed <url> -- /app/server
//
// Credentials are the CLI's: VULNETIX_ORG_ID with VULNETIX_API_KEY, or the
// credentials file `vulnetix auth login` writes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vulnetix/cli/v3/internal/binpkg"
	"github.com/vulnetix/cli/v3/internal/sensor/agent"
	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/dnsguard"
	"github.com/vulnetix/cli/v3/internal/sensor/execguard"
	"github.com/vulnetix/cli/v3/internal/sensor/execwatch"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/inventory"
	"github.com/vulnetix/cli/v3/internal/sensor/proxy"
	"github.com/vulnetix/cli/v3/internal/sensor/siem"
	"github.com/vulnetix/cli/v3/internal/sensor/tetragon"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	// The re-executed half of `run`: installs the seccomp filter and becomes
	// the workload. Does not return there.
	execguard.MaybeChild()

	args := os.Args[1:]
	run := run
	if len(args) > 0 {
		switch args[0] {
		case "inventory":
			run, args = inventoryCmd, args[1:]
		case "lambda-extension":
			run, args = lambdaExtensionCmd, args[1:]
		case "run":
			run, args = guardCmd, args[1:]
		case "tetragon-policy":
			run, args = tetragonPolicyCmd, args[1:]
		}
	}
	err := run(args)
	var exit exitCode
	if errors.As(err, &exit) {
		os.Exit(int(exit))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vulnetix-sensor:", err)
		os.Exit(1)
	}
}

// inventoryCmd prints which installed packages running processes have mapped,
// which of those need a restart, and any code running from anonymous memory.
//
//	vulnetix-sensor inventory [--root /]
func inventoryCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor inventory", flag.ContinueOnError)
	root := fs.String("root", "/", "filesystem whose proc and package databases are read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res := inventory.Scan(*root, binpkg.BuildOwnerIndex(*root))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(res)
}

type options struct {
	mode, listen, upstream, egressListen, feedKey, stateDir, endpoint *string
	tetragonExport, hostRoot, dnsListen, dnsUpstream                  *string
	siemToken, siemURL                                                *string
	hold, inventoryEvery                                              *time.Duration
	offline, showVersion, bpfLSM                                      *bool
	feeds, healthPaths, forward                                       multi
}

// defineFlags is the sensor's whole flag set, in one place so the deploy
// files can be checked against it.
func defineFlags(fs *flag.FlagSet) *options {
	o := &options{
		mode:         fs.String("mode", "monitor", "monitor, guard or enforce"),
		hold:         fs.Duration("hold", 15*time.Minute, "how long guard mode holds a match for a person to decide"),
		listen:       fs.String("listen", "", "address the inbound proxy listens on, e.g. :8080"),
		upstream:     fs.String("upstream", "", "the workload the inbound proxy forwards to, e.g. http://127.0.0.1:8081"),
		egressListen: fs.String("egress-listen", "", "address the outbound proxy listens on, e.g. 127.0.0.1:3128 (set HTTPS_PROXY to it)"),
		feedKey:      fs.String("feed-key", defaultFeedKey(), "base64 Ed25519 public key feeds are signed with (default: VULNETIX_FEED_KEY, else the key pinned at build); without one every rule reports and never blocks"),
		stateDir:     fs.String("state-dir", "/var/lib/vulnetix-sensor", "where the sensor keeps its key"),
		endpoint:     fs.String("endpoint", uplink.DefaultEndpoint, "Vulnetix site API"),
		offline:      fs.Bool("offline", false, "run without reporting to Vulnetix (rules still load from the feeds)"),
		showVersion:  fs.Bool("version", false, "print the version and exit"),
		tetragonExport: fs.String("tetragon-export", "",
			"Tetragon JSON export file (e.g. "+execwatch.DefaultExport+"); every process start is checked against the feeds' file hashes"),
		inventoryEvery: fs.Duration("inventory-every", 6*time.Hour,
			"how often to report which installed packages running processes map (0 turns it off)"),
		hostRoot:    fs.String("host-root", "/", "where the host filesystem is mounted, for hashing what a process ran"),
		bpfLSM:      fs.Bool("bpf-lsm", false, "refuse execs of the exact paths block-mode rules name in the kernel, with a BPF LSM program (needs root and the bpf LSM; untested on a live kernel)"),
		dnsListen:   fs.String("dns-listen", "", "UDP address the DNS guard answers on, e.g. 127.0.0.1:53; point the workload's resolver at it"),
		dnsUpstream: fs.String("dns-upstream", "", "resolver the DNS guard forwards to (default: the first nameserver in /etc/resolv.conf)"),
		// The token's default is read after parsing, so -h never prints it.
		siemToken: fs.String("siem-token", "", "Guardian ingest token (gdn_...) from the console Sources page, for --forward siem (default: VULNETIX_SIEM_TOKEN)"),
		siemURL:   fs.String("siem-url", "", "Guardian events route for --forward siem (default: VULNETIX_SIEM_URL, else "+siem.DefaultURL+")"),
	}
	fs.Var(&o.feeds, "feed", "published detection rule feed URL (repeatable)")
	fs.Var(&o.healthPaths, "health-path", "path a load balancer probes; never held (repeatable)")
	fs.Var(&o.forward, "forward", "also send decisions elsewhere; \"siem\" sends every DNS and egress decision to Guardian (repeatable)")

	return o
}

// tetragonPolicyCmd prints a Tetragon TracingPolicy that refuses, in the
// kernel, execs the feeds' block-mode rules match, and lists on stderr the
// rules it could not express. Nothing is applied: review it, then kubectl
// apply it.
//
//	vulnetix-sensor tetragon-policy --feed <url> > vulnetix-exec-block.yaml
func tetragonPolicyCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor tetragon-policy", flag.ContinueOnError)
	var feeds multi
	fs.Var(&feeds, "feed", "repeatable; a published feed's base URL")
	feedKey := fs.String("feed-key", defaultFeedKey(), "base64 Ed25519 public key the feeds are signed with")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(feeds) == 0 {
		return errors.New("at least one --feed is required")
	}
	if strings.TrimSpace(*feedKey) == "" {
		return errors.New("a feed key is required: an unverified rule never blocks")
	}
	key, err := feed.ParsePublicKey(*feedKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var loaded []feed.Loaded
	for _, f := range feeds {
		l, err := (&feed.Source{BaseURL: f, PublicKey: key}).Fetch(ctx)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		loaded = append(loaded, l)
	}
	out, err := tetragon.Render(loaded)
	for _, s := range out.Skipped {
		fmt.Fprintf(os.Stderr, "skipped %s: %s\n", s.RuleUUID, s.Reason)
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out.YAML)

	return err
}

// exitCode carries a guarded workload's exit code out of run.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("workload exited with %d", int(e)) }

// guardCmd starts a workload under the seccomp exec guard and exits with its
// code. It takes the sensor's flags, then -- and the command.
//
//	vulnetix-sensor run --mode guard --feed <url> -- /app/server
func guardCmd(args []string) error { return runSensor(args, true) }

func run(args []string) error { return runSensor(args, false) }

func runSensor(args []string, guard bool) error {
	fs := flag.NewFlagSet("vulnetix-sensor", flag.ContinueOnError)
	o := defineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var command []string
	if guard {
		command = fs.Args()
		if len(command) == 0 {
			return errors.New("run needs a command after --")
		}
	}
	mode, hold, listen, upstream, egressListen := o.mode, o.hold, o.listen, o.upstream, o.egressListen
	feedKey, stateDir, endpoint, offline, showVersion := o.feedKey, o.stateDir, o.endpoint, o.offline, o.showVersion
	feeds, healthPaths := o.feeds, o.healthPaths
	if *showVersion {
		fmt.Println(version)

		return nil
	}
	if !decide.ValidMode(*mode) {
		return fmt.Errorf("--mode must be monitor, guard or enforce")
	}
	if len(feeds) == 0 {
		return errors.New("at least one --feed is required")
	}
	if !guard && !*o.bpfLSM && *listen == "" && *egressListen == "" && *o.tetragonExport == "" && *o.dnsListen == "" {
		return errors.New("set --listen with --upstream, --egress-listen, --dns-listen, --tetragon-export, or a combination")
	}
	forwarder, err := siemForwarder(o)
	if err != nil {
		return err
	}

	var key []byte
	if strings.TrimSpace(*feedKey) != "" {
		pk, err := feed.ParsePublicKey(*feedKey)
		if err != nil {
			return err
		}
		key = pk
	} else {
		log.Printf("no --feed-key: rules will report and never block")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sensorKey, err := host.SensorKey(*stateDir)
	if err != nil {
		return fmt.Errorf("sensor key in %s: %w", *stateDir, err)
	}
	facts := host.Probe(ctx, nil, "/", nil)

	cfg := agent.Config{
		SensorKey: sensorKey, Version: version, Mode: decide.Mode(*mode), Hold: *hold, Facts: facts,
	}
	for _, f := range feeds {
		cfg.Feeds = append(cfg.Feeds, &feed.Source{BaseURL: f, PublicKey: key})
	}
	if !*offline {
		creds, err := auth.LoadCredentials()
		if err != nil || creds == nil {
			return fmt.Errorf("no Vulnetix credentials: set VULNETIX_ORG_ID and VULNETIX_API_KEY, or run with --offline")
		}
		cfg.Uplink = &uplink.Client{Endpoint: *endpoint, Creds: creds, Version: version}
	}
	if *listen != "" {
		u, err := url.Parse(*upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("--upstream must be a URL such as http://127.0.0.1:8081")
		}
		cfg.Reverse = &proxy.Reverse{Upstream: u, HealthPaths: healthPaths}
		cfg.ReverseListen = *listen
	}
	if *egressListen != "" {
		cfg.Egress = &proxy.Egress{}
		cfg.EgressListen = *egressListen
	}
	cfg.TetragonExport, cfg.HostRoot, cfg.InventoryEvery = *o.tetragonExport, *o.hostRoot, *o.inventoryEvery
	cfg.BPFLSM = *o.bpfLSM
	if *o.dnsListen != "" {
		upstreamDNS := *o.dnsUpstream
		if upstreamDNS == "" {
			conf, _ := os.ReadFile("/etc/resolv.conf")
			upstreamDNS = dnsguard.UpstreamFromResolvConf(string(conf))
		}
		if upstreamDNS == "" {
			return errors.New("--dns-listen needs --dns-upstream: /etc/resolv.conf names no nameserver")
		}
		cfg.DNSListen, cfg.DNSUpstream = *o.dnsListen, upstreamDNS
	}

	cfg.ExecGuard = command
	if forwarder != nil {
		forwarder.Host = facts.Hostname
		cfg.SIEM = forwarder
		log.Printf("sensor: forwarding DNS and egress decisions to %s", forwarder.URL)
	}

	log.Printf("vulnetix-sensor %s: %s on %s (%s), mode %s", version, sensorKey, facts.Hostname, facts.ComputeKind, *mode)

	a := agent.New(cfg)
	if err := a.Run(ctx); err != nil {
		return err
	}
	if guard {
		return exitCode(a.ExitCode)
	}

	return nil
}

// siemForwarder reads --forward, and returns the Guardian forwarder when it
// names siem, nil when nothing is forwarded.
func siemForwarder(o *options) (*siem.Forwarder, error) {
	want := false
	for _, v := range o.forward {
		for _, part := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(part)) {
			case "siem":
				want = true
			case "":
			default:
				return nil, fmt.Errorf("--forward %q: the only destination is siem", part)
			}
		}
	}
	if !want {
		return nil, nil
	}
	if *o.dnsListen == "" && *o.egressListen == "" {
		return nil, errors.New("--forward siem sends DNS and egress decisions: set --dns-listen, --egress-listen or both")
	}
	token := strings.TrimSpace(*o.siemToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VULNETIX_SIEM_TOKEN"))
	}
	if token == "" {
		return nil, errors.New("--forward siem needs a Guardian ingest token: create an Events API token on the console Sources page and pass it with --siem-token or VULNETIX_SIEM_TOKEN")
	}
	endpoint := strings.TrimSpace(*o.siemURL)
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("VULNETIX_SIEM_URL"))
	}
	if endpoint == "" {
		endpoint = siem.DefaultURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return nil, fmt.Errorf("--siem-url must be an https URL such as %s", siem.DefaultURL)
	}

	return &siem.Forwarder{URL: endpoint, Token: token}, nil
}

// isLoopback allows plain http to a local test server only, so the token is
// never sent in the clear over a network.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// pinnedFeedKey is the Vulnetix feed signing public key, set at release build
// with -ldflags "-X main.pinnedFeedKey=<base64>" from the repository variable
// VULNETIX_FEED_PUBLIC_KEY. Empty in a build without it, where a key must be
// given explicitly.
var pinnedFeedKey = ""

// defaultFeedKey is VULNETIX_FEED_KEY when set (a self-hosted feed signer, or
// a rotation in progress), else the key pinned at build.
func defaultFeedKey() string {
	if k := strings.TrimSpace(os.Getenv("VULNETIX_FEED_KEY")); k != "" {
		return k
	}

	return pinnedFeedKey
}
