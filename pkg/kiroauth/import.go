package kiroauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Kiro's IDE keeps its AWS sign-in in the AWS SSO cache, naming the client
// registration by the hash of its client id; kiro-cli keeps the same two values
// in a SQLite database. Importing either shares that sign-in's refresh token
// with the tool that made it, so a device login of the firewall's own is the
// default and import is opt-in.
const kiroTokenFile = "kiro-auth-token.json"

const maxCacheFile = 64 << 10

// ErrSocialLogin means Kiro is signed in with GitHub or Google. Those logins
// refresh through Kiro's own auth service rather than AWS SSO-OIDC, so the
// gateway cannot use them.
var ErrSocialLogin = errors.New("Kiro is signed in with GitHub or Google; only AWS Builder ID and IAM Identity Center sign-ins can be used — run `vulnetix ai-firewall kiro login` without --import")

// CachePath returns the Kiro IDE's token file under home.
func CachePath(home string) string {
	return filepath.Join(home, ".aws", "sso", "cache", kiroTokenFile)
}

var clientHashRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Import reads the Kiro sign-in under home: the Kiro IDE's AWS SSO cache first,
// then kiro-cli's database. It returns the login and the file it came from, or
// os.ErrNotExist (wrapped) when neither has signed in.
func Import(home string) (Login, string, error) {
	l, err := importIDECache(home)
	if err == nil {
		return l, CachePath(home), nil
	}
	cl, db, cerr := importCLI(home)
	switch {
	case cerr == nil:
		return cl, db, nil
	case errors.Is(err, os.ErrNotExist):
		return Login{}, db, cerr
	case errors.Is(cerr, os.ErrNotExist):
		return Login{}, CachePath(home), err
	default:
		return Login{}, CachePath(home), fmt.Errorf("%w; kiro-cli: %w", err, cerr)
	}
}

func importIDECache(home string) (Login, error) {
	path := CachePath(home)
	data, err := readCapped(path)
	if err != nil {
		return Login{}, err
	}
	var tok struct {
		RefreshToken string `json:"refreshToken"`
		AuthMethod   string `json:"authMethod"`
		Provider     string `json:"provider"`
		Region       string `json:"region"`
		ClientIDHash string `json:"clientIdHash"`
		StartURL     string `json:"startUrl"`
		ProfileARN   string `json:"profileArn"`
	}
	if err := json.Unmarshal(data, &tok); err != nil {
		return Login{}, fmt.Errorf("unparseable %s", kiroTokenFile)
	}
	if tok.AuthMethod == "social" || tok.Provider == "Github" || tok.Provider == "Google" {
		return Login{}, ErrSocialLogin
	}
	if tok.RefreshToken == "" || tok.ClientIDHash == "" {
		return Login{}, fmt.Errorf("%s has no AWS sign-in to import", kiroTokenFile)
	}
	if !clientHashRE.MatchString(tok.ClientIDHash) {
		return Login{}, fmt.Errorf("%s names an invalid client registration", kiroTokenFile)
	}
	regData, err := readCapped(filepath.Join(filepath.Dir(path), tok.ClientIDHash+".json"))
	if err != nil {
		return Login{}, fmt.Errorf("Kiro's client registration is missing: %w", err)
	}
	var reg struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		ExpiresAt    string `json:"expiresAt"`
	}
	if err := json.Unmarshal(regData, &reg); err != nil || reg.ClientID == "" || reg.ClientSecret == "" {
		return Login{}, errors.New("Kiro's client registration is unparseable")
	}
	l := Login{
		RefreshToken: tok.RefreshToken,
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		Region:       tok.Region,
		StartURL:     tok.StartURL,
		ProfileARN:   tok.ProfileARN,
	}
	if l.Region == "" {
		l.Region = DefaultRegion
	}
	if !ValidRegion(l.Region) {
		return Login{}, fmt.Errorf("%s has an invalid region", kiroTokenFile)
	}
	if t, err := time.Parse(time.RFC3339, reg.ExpiresAt); err == nil {
		l.ClientSecretExpiresAt = t.Unix()
	}
	if l.StartURL != "" && !ValidStartURL(l.StartURL) {
		l.StartURL = ""
	}
	return l, nil
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCacheFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCacheFile {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	return data, nil
}

// kiro-cli's database keys.
const (
	cliSocialToken  = "kirocli:social:token"
	cliStateProfile = "api.codewhisperer.profile"
	maxCLIOutput    = 256 << 10
)

var (
	cliTokenKeys        = []string{"kirocli:odic:token", "codewhisperer:odic:token"}
	cliRegistrationKeys = []string{"kirocli:odic:device-registration", "codewhisperer:odic:device-registration"}
)

// CLIDatabasePaths returns where kiro-cli keeps its database under home, most
// likely first.
func CLIDatabasePaths(home string) []string {
	linux := filepath.Join(home, ".local", "share", "kiro-cli", "data.sqlite3")
	if x := os.Getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
		linux = filepath.Join(x, "kiro-cli", "data.sqlite3")
	}
	mac := filepath.Join(home, "Library", "Application Support", "kiro-cli", "data.sqlite3")
	if runtime.GOOS == "darwin" {
		return []string{mac, linux}
	}
	return []string{linux, mac}
}

// sqliteQuery runs one read-only query and returns sqlite3's JSON rows. It is a
// variable so tests can stand in for the sqlite3 binary.
var sqliteQuery = runSQLite

// runSQLite runs the system sqlite3 with a fixed argv, read-only, with an
// environment of PATH alone. The output carries secrets, so it is never echoed
// into an error.
func runSQLite(db, query string) ([]byte, error) {
	bin, err := exec.LookPath("sqlite3")
	if err != nil {
		return nil, errors.New("reading kiro-cli's sign-in needs the sqlite3 command; install it, or run `vulnetix ai-firewall kiro login` without --import")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-readonly", "-json", db, query)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("run sqlite3: %w", err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, maxCLIOutput+1))
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if len(out) > maxCLIOutput {
		return nil, errors.New("kiro-cli's database returned too much data")
	}
	if waitErr != nil {
		return nil, errors.New("sqlite3 could not read kiro-cli's database")
	}
	return out, nil
}

func cliRows(out []byte) (map[string]string, error) {
	rows := map[string]string{}
	if len(bytes.TrimSpace(out)) == 0 {
		return rows, nil
	}
	var list []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, errors.New("unparseable kiro-cli database rows")
	}
	for _, r := range list {
		rows[r.Key] = r.Value
	}
	return rows, nil
}

// sqlList renders fixed keys as a quoted SQL list. The keys are constants of
// this package, never input.
func sqlList(keys []string) string {
	q := make([]string, len(keys))
	for i, k := range keys {
		q[i] = "'" + k + "'"
	}
	return strings.Join(q, ",")
}

func importCLI(home string) (Login, string, error) {
	paths := CLIDatabasePaths(home)
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			l, err := readCLI(p)
			return l, p, err
		}
	}
	return Login{}, paths[0], fmt.Errorf("kiro-cli database: %w", os.ErrNotExist)
}

func readCLI(db string) (Login, error) {
	keys := append(append([]string{cliSocialToken}, cliTokenKeys...), cliRegistrationKeys...)
	out, err := sqliteQuery(db, "SELECT key, CAST(value AS TEXT) AS value FROM auth_kv WHERE key IN ("+sqlList(keys)+")")
	if err != nil {
		return Login{}, err
	}
	rows, err := cliRows(out)
	if err != nil {
		return Login{}, err
	}
	first := func(keys []string) string {
		for _, k := range keys {
			if v := rows[k]; v != "" {
				return v
			}
		}
		return ""
	}
	tokData, regData := first(cliTokenKeys), first(cliRegistrationKeys)
	if tokData == "" {
		if rows[cliSocialToken] != "" {
			return Login{}, ErrSocialLogin
		}
		return Login{}, fmt.Errorf("kiro-cli sign-in: %w", os.ErrNotExist)
	}
	var tok struct {
		RefreshToken string `json:"refresh_token"`
		Region       string `json:"region"`
		StartURL     string `json:"start_url"`
		ProfileARN   string `json:"profile_arn"`
	}
	if err := json.Unmarshal([]byte(tokData), &tok); err != nil || tok.RefreshToken == "" {
		return Login{}, errors.New("kiro-cli's token has no AWS sign-in to import")
	}
	if regData == "" {
		return Login{}, errors.New("kiro-cli's client registration is missing")
	}
	var reg struct {
		ClientID     string          `json:"client_id"`
		ClientSecret string          `json:"client_secret"`
		Region       string          `json:"region"`
		ExpiresAt    json.RawMessage `json:"client_secret_expires_at"`
	}
	if err := json.Unmarshal([]byte(regData), &reg); err != nil || reg.ClientID == "" || reg.ClientSecret == "" {
		return Login{}, errors.New("kiro-cli's client registration is unparseable")
	}
	l := Login{
		RefreshToken:          tok.RefreshToken,
		ClientID:              reg.ClientID,
		ClientSecret:          reg.ClientSecret,
		Region:                tok.Region,
		StartURL:              tok.StartURL,
		ProfileARN:            tok.ProfileARN,
		ClientSecretExpiresAt: expiryUnix(reg.ExpiresAt),
	}
	if l.Region == "" {
		l.Region = reg.Region
	}
	if l.Region == "" {
		l.Region = DefaultRegion
	}
	if !ValidRegion(l.Region) {
		return Login{}, errors.New("kiro-cli's sign-in has an invalid region")
	}
	if l.StartURL != "" && !ValidStartURL(l.StartURL) {
		l.StartURL = ""
	}
	if l.ProfileARN == "" {
		l.ProfileARN = cliProfileARN(db)
	}
	return l, nil
}

func cliProfileARN(db string) string {
	out, err := sqliteQuery(db, "SELECT key, CAST(value AS TEXT) AS value FROM state WHERE key IN ("+sqlList([]string{cliStateProfile})+")")
	if err != nil {
		return ""
	}
	rows, err := cliRows(out)
	if err != nil {
		return ""
	}
	var p struct {
		ARN string `json:"arn"`
	}
	if json.Unmarshal([]byte(rows[cliStateProfile]), &p) != nil || !strings.HasPrefix(p.ARN, "arn:aws:codewhisperer:") {
		return ""
	}
	return p.ARN
}

// expiryUnix reads an expiry written as RFC 3339 text or as Unix seconds.
func expiryUnix(raw json.RawMessage) int64 {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Unix()
		}
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	return 0
}
