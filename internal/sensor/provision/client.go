package provision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultEndpoint is the site API.
const DefaultEndpoint = "https://www.vulnetix.com/api/site"

// HTTPClient is used for every provisioning request.
var HTTPClient = &http.Client{Timeout: 60 * time.Second}

// UserAgent is sent on every request.
var UserAgent = "vulnetix-sensor"

// EnrollRequest is what the device says about itself when it enrolls.
type EnrollRequest struct {
	SensorKey   string `json:"sensorKey"`
	Hostname    string `json:"hostname"`
	ComputeKind string `json:"computeKind"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	// Profile asks for a profile by uuid; it must still match.
	Profile string `json:"profile"`
	// MDMDeviceID is the serial or MDM device id, MDM enrolls only.
	MDMDeviceID string `json:"mdmDeviceId,omitempty"`
}

// EnrollResponse is the site's answer to an enroll.
type EnrollResponse struct {
	DeviceUUID string     `json:"deviceUuid"`
	Profile    ProfileRef `json:"profile"`
	Credential struct {
		Scheme string `json:"scheme"`
		Value  string `json:"value"`
	} `json:"credential"`
	Config     Config `json:"config"`
	ConfigEtag string `json:"configEtag"`
}

// StoredCredential is the response's credential, to store for endpoint.
func (r EnrollResponse) StoredCredential(endpoint string) Credential {
	return Credential{Scheme: r.Credential.Scheme, Value: r.Credential.Value, DeviceUUID: r.DeviceUUID, Endpoint: endpoint}
}

// Snapshot is the response's config snapshot.
func (r EnrollResponse) Snapshot() Snapshot {
	return Snapshot{Profile: r.Profile, Config: r.Config, ConfigEtag: r.ConfigEtag}
}

// HTTPError is a refusal from the site, with its error message.
type HTTPError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Message)
	}

	return fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
}

// EnrollWithPerson enrolls with a person's own credential (authHeader is the
// whole Authorization value: "ApiKey <principal>:<hmac>" or "Bearer <token>").
func EnrollWithPerson(ctx context.Context, endpoint, authHeader string, req EnrollRequest) (EnrollResponse, error) {
	req.MDMDeviceID = ""
	var out EnrollResponse
	_, err := call(ctx, endpoint, http.MethodPost, "/v1/runtime/provisioning/enroll", authHeader, nil, req, &out)
	if err == nil && (out.DeviceUUID == "" || out.Credential.Value == "") {
		err = errors.New("enroll: the site returned no device credential")
	}

	return out, err
}

// EnrollMessagePrefix is the first line of the signed MDM enroll message.
const EnrollMessagePrefix = "vulnetix-sensor-enroll/v1"

// EnrollMessage is the exact message an MDM enroll signs.
func EnrollMessage(integration, kid, profile, sensorKey, mdmDeviceID string, ts int64, nonce string) []byte {
	return []byte(strings.Join([]string{
		EnrollMessagePrefix, integration, kid, profile, sensorKey, mdmDeviceID,
		strconv.FormatInt(ts, 10), nonce,
	}, "\n"))
}

// mdmEnrollBody is the body of POST /enroll-mdm.
type mdmEnrollBody struct {
	Integration string `json:"integration"`
	Kid         string `json:"kid"`
	Profile     string `json:"profile"`
	SensorKey   string `json:"sensorKey"`
	MDMDeviceID string `json:"mdmDeviceId"`
	Hostname    string `json:"hostname"`
	ComputeKind string `json:"computeKind"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Version     string `json:"version"`
	TS          int64  `json:"ts"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

// now is the clock MDM enrolls sign with.
var now = time.Now

// signMDMEnroll builds the signed body. privKey is the 32-byte Ed25519 seed
// the site returned (a 64-byte private key is accepted too).
func signMDMEnroll(privKey []byte, integration, kid, profile string, req EnrollRequest) (mdmEnrollBody, error) {
	var key ed25519.PrivateKey
	switch len(privKey) {
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(privKey)
	case ed25519.PrivateKeySize:
		key = ed25519.PrivateKey(privKey)
	default:
		return mdmEnrollBody{}, fmt.Errorf("MDM key is %d bytes, want a 32-byte Ed25519 seed", len(privKey))
	}
	if integration == "" || kid == "" {
		return mdmEnrollBody{}, errors.New("an MDM enroll needs the integration uuid and the key id")
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return mdmEnrollBody{}, err
	}
	b := mdmEnrollBody{
		Integration: integration, Kid: kid, Profile: profile,
		SensorKey: req.SensorKey, MDMDeviceID: req.MDMDeviceID,
		Hostname: req.Hostname, ComputeKind: req.ComputeKind, OS: req.OS, Arch: req.Arch, Version: req.Version,
		TS: now().UnixMilli(), Nonce: hex.EncodeToString(n[:]),
	}
	msg := EnrollMessage(b.Integration, b.Kid, b.Profile, b.SensorKey, b.MDMDeviceID, b.TS, b.Nonce)
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg))

	return b, nil
}

// EnrollWithMDM enrolls with no person, signing with the key the MDM pushed.
func EnrollWithMDM(ctx context.Context, endpoint string, privKeySeed []byte, integration, kid, profile string, req EnrollRequest) (EnrollResponse, error) {
	body, err := signMDMEnroll(privKeySeed, integration, kid, profile, req)
	if err != nil {
		return EnrollResponse{}, err
	}
	var out EnrollResponse
	_, err = call(ctx, endpoint, http.MethodPost, "/v1/runtime/provisioning/enroll-mdm", "", nil, body, &out)
	if err == nil && (out.DeviceUUID == "" || out.Credential.Value == "") {
		err = errors.New("enroll: the site returned no device credential")
	}

	return out, err
}

// ParseKey reads a base64 MDM key file (standard or URL alphabet, padded or
// not, surrounding whitespace ignored).
func ParseKey(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}

	return nil, errors.New("the MDM key is not base64")
}

// ErrRevoked is returned once the site no longer accepts the device's
// credential.
var ErrRevoked = errors.New("the sensor's credential was revoked")

// PollConfig pulls the profile's config. With etag set it asks for a change
// only: changed is false on 304. The etag goes as ?etag= as well as
// If-None-Match, because the worker in front of the site API drops
// If-None-Match. sensorKey is needed with an ApiKey credential only (see
// Credential.SensorKeyParam), which names a person or an org, not the
// device. A 401 is ErrRevoked.
func PollConfig(ctx context.Context, endpoint, authHeader, etag, sensorKey string) (Snapshot, bool, error) {
	h := http.Header{}
	q := url.Values{}
	if etag != "" {
		h.Set("If-None-Match", etag)
		q.Set("etag", etag)
	}
	if sensorKey != "" {
		q.Set("sensorKey", sensorKey)
	}
	path := "/v1/runtime/provisioning/config"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out Snapshot
	status, err := call(ctx, endpoint, http.MethodGet, path, authHeader, h, nil, &out)
	switch {
	case status == http.StatusNotModified:
		return Snapshot{}, false, nil
	case status == http.StatusUnauthorized:
		return Snapshot{}, false, ErrRevoked
	case err != nil:
		return Snapshot{}, false, err
	}
	if out.ConfigEtag != "" && out.ConfigEtag == etag {
		return out, false, nil
	}

	return out, true, nil
}

// ErrUninstallRefused is a 403 from /uninstall: the code is wrong or spent.
var ErrUninstallRefused = errors.New("the site refused the uninstall code")

// Uninstall records the uninstall; a locked sensor needs a code from the
// console first. sensorKey is sent when set (an ApiKey credential needs it).
func Uninstall(ctx context.Context, endpoint, authHeader, code, sensorKey string) error {
	body := map[string]string{"code": code}
	if sensorKey != "" {
		body["sensorKey"] = sensorKey
	}
	status, err := call(ctx, endpoint, http.MethodPost, "/v1/runtime/provisioning/uninstall", authHeader, nil, body, nil)
	if status == http.StatusForbidden {
		return ErrUninstallRefused
	}

	return err
}

// call sends one JSON request and decodes a 2xx answer into out. It returns
// the status code even when it also returns an error.
func call(ctx context.Context, endpoint, method, path, authHeader string, headers http.Header, in, out any) (int, error) {
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, body)
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil
	}
	if resp.StatusCode/100 != 2 {
		e := &HTTPError{Method: method, Path: path, Status: resp.StatusCode}
		var msg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &msg) == nil {
			e.Message = msg.Error
		}

		return resp.StatusCode, e
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: %w", method, path, err)
	}

	return resp.StatusCode, nil
}
