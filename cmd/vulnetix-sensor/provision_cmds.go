package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vulnetix/cli/v4/internal/sensor/host"
	"github.com/vulnetix/cli/v4/internal/sensor/provision"
	"github.com/vulnetix/cli/v4/internal/sensor/uplink"
	"github.com/vulnetix/cli/v4/pkg/auth"
)

// systemctl runs systemctl; replaced in tests.
var systemctl = func(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()

	return strings.TrimSpace(string(out)), err
}

// isRoot is replaced in tests.
var isRoot = func() bool { return os.Geteuid() == 0 }

// unitOptions is where units are written; the zero value is the system.
var unitOptions provision.UnitOptions

// binTarget is where enroll installs the binary; replaced in tests.
var binTarget = provision.DefaultBinPath

func requireRoot(what string) error {
	if !isRoot() {
		return fmt.Errorf("%s needs root: run it with sudo", what)
	}

	return nil
}

// commonFlags are the paths every provisioning subcommand takes.
type commonFlags struct {
	configDir, stateDir, endpoint *string
}

func defineCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		configDir: fs.String("config-dir", provision.DefaultDir, "where the sensor credential and profile config are kept"),
		stateDir:  fs.String("state-dir", "/var/lib/vulnetix-sensor", "where the sensor keeps its key"),
		endpoint:  fs.String("endpoint", "", "Vulnetix site API (default: the endpoint the device enrolled with, else "+provision.DefaultEndpoint+")"),
	}
}

func (c commonFlags) store() provision.Store { return provision.Store{Dir: *c.configDir} }

func (c commonFlags) opts() provision.UnitOptions {
	o := unitOptions
	o.ConfigDir = *c.configDir

	return o
}

// endpointFor is the flag, else the credential's, else the default.
func (c commonFlags) endpointFor(cred provision.Credential) string {
	if *c.endpoint != "" {
		return *c.endpoint
	}
	if cred.Endpoint != "" {
		return cred.Endpoint
	}

	return provision.DefaultEndpoint
}

type enrollOptions struct {
	commonFlags
	fromCLILogin                    *bool
	apiKey, orgID                   *string
	mdmKey, integration, kid, mdmID *string
	profile, protection             *string
	noStart, print                  *bool
}

func defineEnrollFlags(fs *flag.FlagSet) *enrollOptions {
	return &enrollOptions{
		commonFlags:  defineCommon(fs),
		fromCLILogin: fs.Bool("from-cli-login", false, "enroll as the person signed in with `vulnetix auth login` (under sudo, the invoking user's ~/.vulnetix/credentials.json; the keyring is not reachable from sudo, so log in with --store home); the default when no other credential is given"),
		apiKey:       fs.String("api-key", "", "enroll with this personal ApiKey instead (default: VULNETIX_API_KEY); prefer the environment, a flag shows in ps"),
		orgID:        fs.String("org-id", "", "the ApiKey's organisation (default: VULNETIX_ORG_ID)"),
		mdmKey:       fs.String("mdm-key", "", "file holding the MDM integration's base64 Ed25519 private key (32-byte seed); enrolls with no person"),
		integration:  fs.String("integration", "", "MDM integration uuid, with --mdm-key"),
		kid:          fs.String("kid", "", "MDM key id, with --mdm-key"),
		mdmID:        fs.String("mdm-device-id", "", "the device's serial or MDM device id, with --mdm-key (default: the DMI serial, else /etc/machine-id)"),
		profile:      fs.String("profile", "", "ask for this provisioning profile uuid (it must still match)"),
		protection:   fs.String("protection", "", "with --print and no enrolled config: preview standard, hardened or locked"),
		noStart:      fs.Bool("no-start", false, "write the credential, config and units but do not enable or start them"),
		print:        fs.Bool("print", false, "print the units for the enrolled config (or --protection) and exit; contacts nothing and writes nothing"),
	}
}

// enrollCmd enrolls this host with a provisioning profile and installs the
// sensor as a service.
//
//	sudo vulnetix-sensor enroll --from-cli-login
//	sudo vulnetix-sensor enroll --mdm-key /etc/vulnetix/mdm.key --integration <uuid> --kid k1
func enrollCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor enroll", flag.ContinueOnError)
	o := defineEnrollFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := o.store()
	if *o.print {
		snap, _, err := provision.LoadSnapshot(snapshotPaths(store, *o.stateDir)...)
		if err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return err
		}
		if *o.protection != "" {
			snap.Config.Protection = *o.protection
		}
		for _, f := range provision.RenderUnits(snap.Config, provision.DefaultBinPath, o.opts()) {
			fmt.Printf("# %s\n%s\n", f.Path, f.Content)
		}

		return nil
	}
	if err := requireRoot("enroll"); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sensorKey, err := host.SensorKey(*o.stateDir)
	if err != nil {
		return fmt.Errorf("sensor key in %s: %w", *o.stateDir, err)
	}
	facts := host.Probe(ctx, nil, "/", nil)
	req := provision.EnrollRequest{
		SensorKey: sensorKey, Hostname: facts.Hostname, ComputeKind: facts.ComputeKind,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version, Profile: *o.profile,
	}
	endpoint := *o.endpoint
	if endpoint == "" {
		endpoint = provision.DefaultEndpoint
	}
	provision.UserAgent = "vulnetix-sensor/" + version

	var res provision.EnrollResponse
	if *o.mdmKey != "" {
		raw, err := os.ReadFile(*o.mdmKey)
		if err != nil {
			return fmt.Errorf("--mdm-key: %w", err)
		}
		seed, err := provision.ParseKey(raw)
		if err != nil {
			return fmt.Errorf("--mdm-key %s: %w", *o.mdmKey, err)
		}
		req.MDMDeviceID = *o.mdmID
		if req.MDMDeviceID == "" {
			req.MDMDeviceID = machineID()
		}
		res, err = provision.EnrollWithMDM(ctx, endpoint, seed, *o.integration, *o.kid, *o.profile, req)
		if err != nil {
			return err
		}
	} else {
		creds, err := personCredentials(*o.apiKey, *o.orgID)
		if err != nil {
			return err
		}
		h := auth.GetAuthHeader(creds)
		if h == "" {
			return errors.New("the signed-in credential cannot be sent as a person: log in again with `vulnetix auth login --store home`")
		}
		res, err = provision.EnrollWithPerson(ctx, endpoint, h, req)
		if err != nil {
			return err
		}
	}

	if err := store.SaveCredential(res.StoredCredential(endpoint)); err != nil {
		return err
	}
	snap := res.Snapshot()
	if err := store.SaveSnapshot(snap); err != nil {
		return err
	}
	// What the previous enrolment pulled is not this profile's.
	_ = os.Remove(filepath.Join(*o.stateDir, "config.json"))

	binPath, err := installBinary(binTarget)
	if err != nil {
		return err
	}
	if legacyEnvHasCredentials() {
		fmt.Fprintf(os.Stderr, "warning: %s sets Vulnetix credentials, which win over the device credential; remove them to report as this device\n", provision.LegacyEnvFile)
	}
	if _, err := syncUnits(snap.Config, binPath, o.opts()); err != nil {
		return err
	}
	level := snap.Config.Level()
	started := "not started (--no-start)"
	if !*o.noStart {
		wasActive := isActive()
		if out, err := systemctl("daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
		for _, u := range []string{provision.GuardTimerUnit, provision.ServiceUnit} {
			if out, err := systemctl("enable", "--now", u); err != nil {
				return fmt.Errorf("systemctl enable --now %s: %v: %s", u, err, out)
			}
		}
		if wasActive {
			// A restart is a manual stop, which a hardened unit refuses; the
			// sensor exits on SIGHUP and systemd starts it on the new config.
			_, _ = systemctl("kill", "--kill-whom=main", "--signal=SIGHUP", provision.ServiceUnit)
		}
		started = "running"
	}

	fmt.Printf("Enrolled %s as device %s\n", facts.Hostname, res.DeviceUUID)
	fmt.Printf("  profile     %s (%s)\n", res.Profile.Name, res.Profile.UUID)
	fmt.Printf("  credential  %s, in %s\n", res.Credential.Scheme, store.CredentialPath())
	fmt.Printf("  mode        %s\n", orDefault(snap.Config.Mode, "monitor"))
	fmt.Printf("  protection  %s\n", level)
	fmt.Printf("  feeds       %d\n", len(snap.Config.Feeds))
	fmt.Printf("  service     %s (%s)\n", provision.ServiceUnit, started)

	return nil
}

// personCredentials is the person enrolling: --api-key with --org-id, else
// the CLI's own credentials. Under sudo, the CLI's home store is the invoking
// user's, not root's.
func personCredentials(apiKey, orgID string) (*auth.Credentials, error) {
	if apiKey == "" {
		apiKey = os.Getenv("VULNETIX_API_KEY")
	}
	if orgID == "" {
		orgID = os.Getenv("VULNETIX_ORG_ID")
	}
	if apiKey != "" {
		if orgID == "" {
			return nil, errors.New("--api-key needs --org-id (or VULNETIX_ORG_ID)")
		}

		return &auth.Credentials{OrgID: orgID, APIKey: apiKey, Method: auth.DirectAPIKey}, nil
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && os.Getenv(auth.CredentialsDirEnv) == "" {
		if u, err := user.Lookup(sudoUser); err == nil && u.HomeDir != "" {
			_ = os.Setenv(auth.CredentialsDirEnv, filepath.Join(u.HomeDir, ".vulnetix"))
		}
	}
	creds, err := auth.LoadCredentials()
	if err != nil {
		if strings.Contains(err.Error(), "keyring") {
			return nil, fmt.Errorf("%w\nthe keyring is not reachable under sudo: run `vulnetix auth login --store home` as yourself, then enroll again", err)
		}

		return nil, fmt.Errorf("%w\nsign in first with `vulnetix auth login --store home`, or pass --api-key and --org-id", err)
	}

	return creds, nil
}

// machineID is the device's identity for an MDM enroll.
func machineID() string {
	for _, p := range []string{"/sys/class/dmi/id/product_serial", "/etc/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" && !strings.EqualFold(s, "none") {
				return s
			}
		}
	}

	return ""
}

// installBinary puts this executable at target, unless it is already there.
// The unit runs as a dynamic user with ProtectHome, so a binary in a home
// directory could not be run by it.
func installBinary(target string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if t, err := filepath.EvalSymlinks(target); err == nil && t == self {
		return target, nil
	}
	in, err := os.Open(self)
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".vulnetix-sensor.*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()

		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()

		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	// A rename replaces a running binary without "text file busy".
	if err := os.Rename(tmp.Name(), target); err != nil {
		return "", err
	}

	return target, nil
}

func legacyEnvHasCredentials() bool {
	b, err := os.ReadFile(provision.LegacyEnvFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		for _, k := range []string{"VULNETIX_API_KEY=", "VULNETIX_API_TOKEN=", "VVD_SECRET="} {
			if strings.HasPrefix(line, k) && len(line) > len(k) {
				return true
			}
		}
	}

	return false
}

// syncUnits writes the units for cfg where they differ from what is on disk,
// and removes the polkit rule below hardened. It reports whether anything
// changed.
func syncUnits(cfg provision.Config, binPath string, opts provision.UnitOptions) (bool, error) {
	changed := false
	files := provision.RenderUnits(cfg, binPath, opts)
	wantPolkit := false
	for _, f := range files {
		if f.Path == opts.PolkitRulePath() {
			wantPolkit = true
		}
		if cur, err := os.ReadFile(f.Path); err == nil && string(cur) == f.Content {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			return changed, err
		}
		if err := os.WriteFile(f.Path, []byte(f.Content), f.Mode); err != nil {
			return changed, err
		}
		changed = true
	}
	if !wantPolkit {
		if err := os.Remove(opts.PolkitRulePath()); err == nil {
			changed = true
		}
	}

	return changed, nil
}

func isActive() bool {
	out, _ := systemctl("is-active", provision.ServiceUnit)

	return out == "active" || out == "activating" || out == "reloading"
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}

	return s
}

// statusCmd says whether this host is enrolled and the sensor running. It
// exits 3 when the service is not active.
func statusCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor status", flag.ContinueOnError)
	c := defineCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := c.store()
	snap, path, snapErr := provision.LoadSnapshot(snapshotPaths(store, *c.stateDir)...)
	state, _ := systemctl("is-active", provision.ServiceUnit)
	if state == "" {
		state = "unknown"
	}
	enabled, _ := systemctl("is-enabled", provision.ServiceUnit)

	fmt.Printf("enrolled     %v\n", store.HasCredential())
	if snapErr == nil {
		fmt.Printf("profile      %s (%s)\n", orDefault(snap.Profile.Name, "?"), snap.Profile.UUID)
		fmt.Printf("protection   %s\n", snap.Config.Level())
		fmt.Printf("mode         %s\n", orDefault(snap.Config.Mode, "monitor"))
		fmt.Printf("config etag  %s (%s)\n", orDefault(snap.ConfigEtag, "(none)"), path)
	} else {
		fmt.Printf("profile      none (%v)\n", snapErr)
	}
	fmt.Printf("service      %s, %s\n", state, orDefault(enabled, "unknown"))
	if state != "active" {
		return exitCode(3)
	}

	return nil
}

// configCmd prints the profile config the sensor runs.
func configCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor config", flag.ContinueOnError)
	c := defineCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	snap, _, err := provision.LoadSnapshot(snapshotPaths(c.store(), *c.stateDir)...)
	if errors.Is(err, iofs.ErrNotExist) {
		return errors.New("not enrolled: no profile config (run vulnetix-sensor enroll)")
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	return enc.Encode(snap)
}

func readSensorKey(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, "sensor-key"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}

func uplinkFor(endpoint string, cred provision.Credential) *uplink.Client {
	return &uplink.Client{Endpoint: endpoint, Authorization: cred.AuthHeader, Version: version}
}

type goodbyeOptions struct {
	commonFlags
	reason, detail *string
}

func defineGoodbyeFlags(fs *flag.FlagSet) *goodbyeOptions {
	return &goodbyeOptions{
		commonFlags: defineCommon(fs),
		reason:      fs.String("reason", "stop", "signal, stop, uninstall or upgrade"),
		detail:      fs.String("detail", "", "free text shown with the stop in the console"),
	}
}

// goodbyeCmd tells the console the sensor stopped, and why.
func goodbyeCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor goodbye", flag.ContinueOnError)
	o := defineGoodbyeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch *o.reason {
	case "signal", "stop", "uninstall", "upgrade":
	default:
		return errors.New("--reason must be signal, stop, uninstall or upgrade")
	}
	cred, err := o.store().LoadCredential()
	if err != nil {
		return err
	}
	key := readSensorKey(*o.stateDir)
	if key == "" {
		return fmt.Errorf("no sensor key in %s", *o.stateDir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return uplinkFor(o.endpointFor(cred), cred).Goodbye(ctx, key, *o.reason, *o.detail)
}

// guardCheckCmd runs from the guard timer, as root, once a minute. It keeps
// the units in step with the profile and, from hardened up, restores a
// sensor that was masked, disabled or stopped, and reports that it had been.
func guardCheckCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor guard-check", flag.ContinueOnError)
	c := defineCommon(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := c.store()
	if !store.HasCredential() || store.Uninstalling() {
		return nil
	}
	snap, _, err := provision.LoadSnapshot(snapshotPaths(store, *c.stateDir)...)
	if err != nil {
		return err
	}
	binPath, err := os.Executable()
	if err != nil {
		binPath = provision.DefaultBinPath
	}
	if !strings.HasPrefix(binPath, "/usr/") {
		binPath = provision.DefaultBinPath
	}
	changed, err := syncUnits(snap.Config, binPath, c.opts())
	if err != nil {
		return err
	}
	if changed {
		_, _ = systemctl("daemon-reload")
		_, _ = systemctl("enable", provision.GuardTimerUnit)
		if isActive() {
			_, _ = systemctl("kill", "--kill-whom=main", "--signal=SIGHUP", provision.ServiceUnit)
		}
		fmt.Printf("guard: units updated for protection %s\n", snap.Config.Level())
	}
	unlock, locked := lockUpdate(*c.stateDir)
	if !locked {
		return nil // the rescue or an earlier guard is mid-update
	}
	defer unlock()
	if action, outcome, err := reconcilePending(*c.stateDir, binPath, time.Now(), serviceFailed(), serverReachable(c, store)); err != nil {
		fmt.Fprintf(os.Stderr, "guard: rollback failed: %v\n", err)
	} else if action != "" {
		announceOutcome(c, store, outcome)
	}
	if tag, err := maybeSelfUpdate(context.Background(), snap.Config.AutoUpdateOn(), snap.Config.AllowMajorUpdateOn(), version, binPath, *c.stateDir, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "guard: self-update not applied: %v\n", err)
	} else if tag != "" {
		if cred, err := store.LoadCredential(); err == nil {
			if key := readSensorKey(*c.stateDir); key != "" {
				sayGoodbye(uplinkFor(c.endpointFor(cred), cred), key, "upgrade", "self-update from "+version+" to "+tag)
			}
		}
		if isActive() {
			_, _ = systemctl("kill", "--kill-whom=main", "--signal=SIGHUP", provision.ServiceUnit)
		}
		fmt.Printf("guard: sensor updated %s -> %s\n", version, tag)
	}
	if snap.Config.Level() == provision.Standard {
		return nil
	}

	var restored []string
	enabled, _ := systemctl("is-enabled", provision.ServiceUnit)
	switch enabled {
	case "masked", "masked-runtime":
		_, _ = systemctl("unmask", provision.ServiceUnit)
		_, _ = systemctl("enable", provision.ServiceUnit)
		restored = append(restored, "was masked")
	case "disabled":
		_, _ = systemctl("enable", provision.ServiceUnit)
		restored = append(restored, "was disabled")
	}
	start := false
	if !isActive() && !snap.Config.UserMayStop() {
		restored = append(restored, "was not running")
		start = true
	}
	if len(restored) == 0 {
		return nil
	}
	detail := "restored by guard: " + strings.Join(restored, ", ")
	if cred, err := store.LoadCredential(); err == nil {
		if key := readSensorKey(*c.stateDir); key != "" {
			sayGoodbye(uplinkFor(c.endpointFor(cred), cred), key, "stop", detail)
		}
	}
	if start {
		if out, err := systemctl("start", provision.ServiceUnit); err != nil {
			return fmt.Errorf("guard: start %s: %v: %s", provision.ServiceUnit, err, out)
		}
	}
	fmt.Println("guard: " + detail)

	return nil
}

type uninstallOptions struct {
	commonFlags
	code *string
}

func defineUninstallFlags(fs *flag.FlagSet) *uninstallOptions {
	return &uninstallOptions{
		commonFlags: defineCommon(fs),
		code:        fs.String("code", "", "the one-time uninstall code from the console, required when the profile is locked"),
	}
}

// uninstallCmd removes the sensor's service, guard, polkit rule, credential
// and config, and tells the site. A locked sensor needs a code from the
// console, checked by the site before anything is stopped.
func uninstallCmd(args []string) error {
	fs := flag.NewFlagSet("vulnetix-sensor uninstall", flag.ContinueOnError)
	o := defineUninstallFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot("uninstall"); err != nil {
		return err
	}
	store := o.store()
	snap, _, _ := provision.LoadSnapshot(snapshotPaths(store, *o.stateDir)...)
	locked := snap.Config.Level() == provision.Locked
	if locked && *o.code == "" {
		return errors.New("this sensor's profile is locked: get an uninstall code for this device from the console and pass --code")
	}
	cred, credErr := store.LoadCredential()
	if credErr != nil && !errors.Is(credErr, provision.ErrNoCredential) {
		return credErr
	}
	enrolled := credErr == nil

	// The marker stops the sensor reporting its own stop as a signal, and
	// the guard restoring it.
	if err := os.MkdirAll(*o.configDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(store.UninstallingPath(), nil, 0o644); err != nil {
		return err
	}
	if enrolled {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		endpoint := o.endpointFor(cred)
		key := readSensorKey(*o.stateDir)
		goodbye := func() {
			if key != "" {
				sayGoodbye(uplinkFor(endpoint, cred), key, "uninstall", "")
			}
		}
		if locked {
			// The code is checked before anything stops; a good one also
			// revokes the device, so the goodbye after it may be refused.
			if err := provision.Uninstall(ctx, endpoint, cred.AuthHeader(), *o.code, cred.SensorKeyParam(key)); err != nil {
				_ = os.Remove(store.UninstallingPath())

				return fmt.Errorf("uninstall not allowed: %w", err)
			}
			goodbye()
		} else {
			goodbye()
			if err := provision.Uninstall(ctx, endpoint, cred.AuthHeader(), "", cred.SensorKeyParam(key)); err != nil {
				fmt.Fprintf(os.Stderr, "warning: the site did not record the uninstall: %v\n", err)
			}
		}
	}

	// A hardened unit refuses a manual stop, so its files go first: once
	// they are gone and systemd has reloaded, the running unit can stop.
	units := []string{provision.GuardTimerUnit, provision.GuardServiceUnit, provision.ServiceUnit}
	for _, u := range units {
		_, _ = systemctl("disable", u)
	}
	for _, p := range o.opts().UnitPaths() {
		if err := os.Remove(p); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			return err
		}
	}
	_, _ = systemctl("daemon-reload")
	for _, u := range units {
		if _, err := systemctl("stop", u); err != nil {
			_, _ = systemctl("kill", u)
		}
		_, _ = systemctl("reset-failed", u)
	}

	var errs []error
	for _, p := range []string{store.CredentialPath(), store.ConfigPath(), filepath.Join(*o.stateDir, "config.json"), store.UninstallingPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, iofs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(*o.configDir) // only when empty
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Printf("vulnetix-sensor uninstalled (the binary %s and the sensor key in %s are left)\n", provision.DefaultBinPath, *o.stateDir)

	return nil
}

// subcommandFlagSets is every subcommand's flags, for the deploy-file check.
func subcommandFlagSets() []*flag.FlagSet {
	var out []*flag.FlagSet
	mk := func(name string, define func(*flag.FlagSet)) {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		define(fs)
		out = append(out, fs)
	}
	mk("enroll", func(fs *flag.FlagSet) { defineEnrollFlags(fs) })
	mk("uninstall", func(fs *flag.FlagSet) { defineUninstallFlags(fs) })
	mk("goodbye", func(fs *flag.FlagSet) { defineGoodbyeFlags(fs) })
	mk("status", func(fs *flag.FlagSet) { defineCommon(fs) })
	mk("inventory", func(fs *flag.FlagSet) { defineInventoryFlags(fs) })

	return out
}
