package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/agent"
	"github.com/vulnetix/cli/v4/internal/sensor/decide"
	"github.com/vulnetix/cli/v4/internal/sensor/provision"
	"github.com/vulnetix/cli/v4/internal/sensor/uplink"
)

// snapshotPaths is where a config snapshot can be: the one enroll writes,
// and the one the running sensor writes to its state directory (it cannot
// write /etc). The newer wins.
func snapshotPaths(store provision.Store, stateDir string) []string {
	return []string{store.ConfigPath(), filepath.Join(stateDir, "config.json")}
}

// explicitFlags is the flags given on the command line.
func explicitFlags(fs *flag.FlagSet) map[string]bool {
	out := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { out[f.Name] = true })

	return out
}

// applySnapshot sets every flag the profile config has a value for and the
// command line did not give.
func applySnapshot(fs *flag.FlagSet, explicit map[string]bool, cfg provision.Config) error {
	set := func(name, value string) error {
		if explicit[name] {
			return nil
		}

		return fs.Set(name, value)
	}
	if cfg.Mode != "" {
		if err := set("mode", cfg.Mode); err != nil {
			return err
		}
	}
	if cfg.Hold != "" {
		if err := set("hold", cfg.Hold); err != nil {
			return err
		}
	}
	if cfg.InventoryEvery != "" {
		if err := set("inventory-every", cfg.InventoryEvery); err != nil {
			return err
		}
	}
	// "" keeps the key pinned at build.
	if cfg.FeedKey != "" {
		if err := set("feed-key", cfg.FeedKey); err != nil {
			return err
		}
	}
	// "" in the profile turns the listener off.
	if err := set("egress-listen", cfg.EgressListen); err != nil {
		return err
	}
	if err := set("dns-listen", cfg.DNSListen); err != nil {
		return err
	}
	if !explicit["feed"] {
		for _, f := range cfg.Feeds {
			if err := fs.Set("feed", f); err != nil {
				return err
			}
		}
	}
	if !explicit["forward"] {
		for _, f := range cfg.Forward {
			if err := fs.Set("forward", f); err != nil {
				return err
			}
		}
	}

	return nil
}

// explicitCredentialEnv is whether the environment names credentials, which
// win over an enrolled device's.
func explicitCredentialEnv() bool {
	return os.Getenv("VULNETIX_API_TOKEN") != "" ||
		(os.Getenv("VULNETIX_API_KEY") != "" && os.Getenv("VULNETIX_ORG_ID") != "") ||
		(os.Getenv("VVD_ORG") != "" && os.Getenv("VVD_SECRET") != "")
}

func shortEtag(etag string) string {
	if len(etag) > 12 {
		return etag[:12]
	}
	if etag == "" {
		return "(none)"
	}

	return etag
}

// liveChange is what a config change needs from the running sensor.
type liveChange struct {
	Mode, Hold, Feeds bool
	// Restart is a change the sensor cannot make while it runs: a listener,
	// forwarding or the inventory interval.
	Restart bool
}

// diffConfig compares two profile configs, ignoring what the command line
// fixed. Protection and allowUserStop are unit settings, which the guard
// applies; heartbeatAlertMinutes is the site's.
func diffConfig(old, cur provision.Config, explicit map[string]bool) liveChange {
	var c liveChange
	c.Mode = !explicit["mode"] && cur.Mode != "" && cur.Mode != old.Mode
	c.Hold = !explicit["hold"] && cur.Hold != "" && cur.Hold != old.Hold
	c.Feeds = (!explicit["feed"] && !slices.Equal(old.Feeds, cur.Feeds)) ||
		(!explicit["feed-key"] && old.FeedKey != cur.FeedKey)
	c.Restart = (!explicit["egress-listen"] && old.EgressListen != cur.EgressListen) ||
		(!explicit["dns-listen"] && old.DNSListen != cur.DNSListen) ||
		(!explicit["forward"] && !slices.Equal(old.Forward, cur.Forward)) ||
		(!explicit["inventory-every"] && old.InventoryEvery != cur.InventoryEvery)

	return c
}

// configPoller pulls the profile's config for the agent's config tick. A
// change it can make live (mode, hold, feeds) it makes; anything else stops
// the agent so systemd starts it on the new config. A revoked credential
// stops reporting, and the sensor stays up offline rather than flapping.
//
// flagFeeds and flagFeedKey are what the sensor started with, used where the
// command line fixed them.
func configPoller(endpoint string, cred provision.Credential, snap provision.Snapshot, explicit map[string]bool, statePath string, flagFeeds []string, flagFeedKey, sensorKey string, site *uplink.Client) func(context.Context, *agent.Agent) bool {
	etag, current := snap.ConfigEtag, snap.Config
	revoked := false

	return func(ctx context.Context, a *agent.Agent) bool {
		if revoked {
			return false
		}
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		next, changed, err := provision.PollConfig(pctx, endpoint, cred.AuthHeader(), etag, cred.SensorKeyParam(sensorKey))
		switch {
		case errors.Is(err, provision.ErrRevoked):
			revoked = true
			log.Printf("sensor: DEVICE REVOKED: the site refused this device's credential (device %s). The sensor keeps enforcing the rules it has and reports nothing more. Re-enroll with: sudo vulnetix-sensor enroll", cred.DeviceUUID)
			a.StopReporting()

			return false
		case err != nil:
			log.Printf("sensor: profile config not pulled: %v", err)

			return false
		case !changed:
			return false
		}
		if err := provision.SaveSnapshotAt(statePath, next); err != nil {
			log.Printf("sensor: profile config not saved to %s: %v", statePath, err)
		}
		log.Printf("sensor: profile %q config changed (%s -> %s)", next.Profile.Name, shortEtag(etag), shortEtag(next.ConfigEtag))
		d := diffConfig(current, next.Config, explicit)
		etag, current = next.ConfigEtag, next.Config
		a.SetConfigEtag(etag)
		if d.Restart {
			return true
		}
		if d.Mode && decide.ValidMode(next.Config.Mode) {
			a.SetMode(decide.Mode(next.Config.Mode))
			log.Printf("sensor: mode is now %s", next.Config.Mode)
		}
		if d.Hold {
			if h, err := time.ParseDuration(next.Config.Hold); err == nil {
				a.SetHold(h)
			}
		}
		if d.Feeds {
			keyText := next.Config.FeedKey
			switch {
			case explicit["feed-key"]:
				keyText = flagFeedKey
			case keyText == "":
				keyText = defaultFeedKey()
			}
			key, err := parseFeedKey(keyText)
			if err != nil {
				log.Printf("sensor: profile feed key refused, restarting to apply the profile: %v", err)

				return true
			}
			feeds := next.Config.Feeds
			if explicit["feed"] {
				feeds = flagFeeds
			}
			a.SetFeeds(feedSources(feeds, key, site))
			log.Printf("sensor: feeds are now %v", feeds)
		}

		return false
	}
}
