package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/agent"
	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/host"
	"github.com/vulnetix/cli/v3/internal/sensor/lambdaext"
	"github.com/vulnetix/cli/v3/internal/sensor/proxy"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

// lambdaExtensionCmd runs the sensor as a Lambda external extension. It is
// configured by environment variables on the function, because Lambda starts
// an extension with no arguments:
//
//	VULNETIX_SENSOR_FEEDS   comma-separated published feed URLs (required)
//	VULNETIX_FEED_KEY       base64 Ed25519 key the feeds are signed with
//	VULNETIX_SENSOR_MODE    monitor (default), guard or enforce
//	VULNETIX_SENSOR_PORT    Runtime API proxy port, default 9009
//	VULNETIX_SENSOR_EGRESS  egress proxy port when set (the wrapper exports HTTPS_PROXY)
//	VULNETIX_ORG_ID, VULNETIX_API_KEY  credentials, as for the CLI
func lambdaExtensionCmd(_ []string) error {
	realAPI := os.Getenv("AWS_LAMBDA_RUNTIME_API")
	if realAPI == "" {
		return errors.New("AWS_LAMBDA_RUNTIME_API is not set: this runs inside Lambda only")
	}
	mode := decide.Mode(envOr("VULNETIX_SENSOR_MODE", "monitor"))
	if !decide.ValidMode(string(mode)) {
		return fmt.Errorf("VULNETIX_SENSOR_MODE must be monitor, guard or enforce")
	}
	var feeds []string
	for _, f := range strings.Split(os.Getenv("VULNETIX_SENSOR_FEEDS"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			feeds = append(feeds, f)
		}
	}
	if len(feeds) == 0 {
		return errors.New("VULNETIX_SENSOR_FEEDS is required")
	}
	var key []byte
	if k := defaultFeedKey(); k != "" {
		pk, err := feed.ParsePublicKey(k)
		if err != nil {
			return err
		}
		key = pk
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// /tmp is the only writable place in Lambda; the key lives as long as the
	// execution environment, which is what a sensor in Lambda is.
	sensorKey, err := host.SensorKey("/tmp/vulnetix-sensor")
	if err != nil {
		return err
	}
	cfg := agent.Config{
		SensorKey: sensorKey, Version: version, Mode: mode, Facts: host.Probe(ctx, nil, "/", nil),
		// Lambda freezes the environment between invocations, so the agent
		// flushes on every invoke rather than waiting on a ticker.
		FlushEvery: time.Second,
	}
	for _, f := range feeds {
		cfg.Feeds = append(cfg.Feeds, &feed.Source{BaseURL: f, PublicKey: key})
	}
	if creds, err := auth.LoadCredentials(); err == nil && creds != nil {
		cfg.Uplink = &uplink.Client{Endpoint: envOr("VULNETIX_ENDPOINT", uplink.DefaultEndpoint), Creds: creds, Version: version}
	} else {
		log.Printf("vulnetix-sensor: no credentials; rules load and nothing is reported")
	}
	if port := os.Getenv("VULNETIX_SENSOR_EGRESS"); port != "" {
		cfg.Egress = &proxy.Egress{}
		cfg.EgressListen = "127.0.0.1:" + port
	}
	a := agent.New(cfg)

	// Listen before registering: Lambda starts the runtime once every
	// extension has registered, and the runtime's first call comes here.
	ln, err := net.Listen("tcp", "127.0.0.1:"+envOr("VULNETIX_SENSOR_PORT", "9009"))
	if err != nil {
		return err
	}
	rp := &lambdaext.RuntimeProxy{Upstream: realAPI, Rules: a.Rules.Load, Verdicts: a.Verdicts, Report: a.Enqueue}
	go func() { _ = http.Serve(ln, rp) }()

	client := &http.Client{}
	id, err := lambdaext.Register(ctx, client, realAPI, "vulnetix-sensor")
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	err = lambdaext.Events(ctx, client, realAPI, id, func() { a.Flush(ctx) })
	cancel()
	<-done

	return err
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}

	return fallback
}
