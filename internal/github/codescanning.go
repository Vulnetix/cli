package github

// Code scanning upload: POST /repos/{owner}/{repo}/code-scanning/sarifs with
// the SARIF gzipped and base64-encoded, then GET .../sarifs/{id} until GitHub
// has processed it. Needs `security-events: write` (and `actions: read` on a
// private repository).

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// SARIFUpload is one upload's id and processing state.
type SARIFUpload struct {
	ID               string   `json:"id"`
	URL              string   `json:"url"`
	ProcessingStatus string   `json:"processing_status,omitempty"`
	AnalysesURL      string   `json:"analyses_url,omitempty"`
	Errors           []string `json:"errors,omitempty"`
}

// MaxSARIFUploadBytes is code scanning's limit on the gzipped document.
const MaxSARIFUploadBytes = 10 << 20

// EncodeSARIF gzips and base64-encodes a SARIF document as the API wants.
func EncodeSARIF(sarifJSON []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(sarifJSON); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	if buf.Len() > MaxSARIFUploadBytes {
		return "", fmt.Errorf("SARIF is %d bytes gzipped; code scanning accepts at most %d", buf.Len(), MaxSARIFUploadBytes)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// UploadSARIF posts one SARIF document for the target commit and ref.
func (c *Client) UploadSARIF(ctx context.Context, t Target, sarifJSON []byte, checkoutURI string) (*SARIFUpload, error) {
	enc, err := EncodeSARIF(sarifJSON)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"commit_sha": t.SHA,
		"ref":        t.Ref,
		"sarif":      enc,
		"tool_name":  "vulnetix",
	}
	if checkoutURI != "" {
		body["checkout_uri"] = checkoutURI
	}
	var up SARIFUpload
	if _, err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/code-scanning/sarifs", t.Repo), body, &up); err != nil {
		return nil, err
	}
	return &up, nil
}

// WaitSARIF polls an upload until it is complete or failed, or until timeout.
// A timeout is not an error: GitHub keeps processing, and the upload stands.
func (c *Client) WaitSARIF(ctx context.Context, repo, id string, timeout, interval time.Duration) (*SARIFUpload, error) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		var st SARIFUpload
		if _, err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/code-scanning/sarifs/%s", repo, id), nil, &st); err != nil {
			return nil, err
		}
		st.ID = id
		switch st.ProcessingStatus {
		case "complete":
			return &st, nil
		case "failed":
			return &st, fmt.Errorf("code scanning could not process the upload: %v", st.Errors)
		}
		if time.Now().Add(interval).After(deadline) {
			return &st, nil
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return &st, ctx.Err()
		case <-t.C:
		}
	}
}
