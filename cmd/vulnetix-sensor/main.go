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
	"github.com/vulnetix/cli/v3/internal/sensor/execwatch"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/inventory"
	"github.com/vulnetix/cli/v3/internal/sensor/proxy"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	args := os.Args[1:]
	run := run
	if len(args) > 0 && args[0] == "inventory" {
		run, args = inventoryCmd, args[1:]
	}
	if err := run(args); err != nil {
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
	hold                                                              *time.Duration
	offline, showVersion                                              *bool
	feeds, healthPaths                                                multi
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
		feedKey:      fs.String("feed-key", os.Getenv("VULNETIX_FEED_KEY"), "base64 Ed25519 public key feeds are signed with; without it every rule reports and never blocks"),
		stateDir:     fs.String("state-dir", "/var/lib/vulnetix-sensor", "where the sensor keeps its key"),
		endpoint:     fs.String("endpoint", uplink.DefaultEndpoint, "Vulnetix site API"),
		offline:      fs.Bool("offline", false, "run without reporting to Vulnetix (rules still load from the feeds)"),
		showVersion:  fs.Bool("version", false, "print the version and exit"),
		tetragonExport: fs.String("tetragon-export", "",
			"Tetragon JSON export file (e.g. "+execwatch.DefaultExport+"); every process start is checked against the feeds' file hashes"),
		hostRoot:    fs.String("host-root", "/", "where the host filesystem is mounted, for hashing what a process ran"),
		dnsListen:   fs.String("dns-listen", "", "UDP address the DNS guard answers on, e.g. 127.0.0.1:53; point the workload's resolver at it"),
		dnsUpstream: fs.String("dns-upstream", "", "resolver the DNS guard forwards to (default: the first nameserver in /etc/resolv.conf)"),
	}
	fs.Var(&o.feeds, "feed", "published detection rule feed URL (repeatable)")
	fs.Var(&o.healthPaths, "health-path", "path a load balancer probes; never held (repeatable)")

	return o
}

func run(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor", flag.ContinueOnError)
	o := defineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
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
	if *listen == "" && *egressListen == "" && *o.tetragonExport == "" && *o.dnsListen == "" {
		return errors.New("set --listen with --upstream, --egress-listen, --dns-listen, --tetragon-export, or a combination")
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
	cfg.TetragonExport, cfg.HostRoot = *o.tetragonExport, *o.hostRoot
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

	log.Printf("vulnetix-sensor %s: %s on %s (%s), mode %s", version, sensorKey, facts.Hostname, facts.ComputeKind, *mode)

	return agent.New(cfg).Run(ctx)
}
