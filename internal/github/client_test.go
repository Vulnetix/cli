package github

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetAllFollowsPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/items?page=2>; rel="next", <%s/items?page=2>; rel="last"`, srv.URL, srv.URL))
			_, _ = io.WriteString(w, `[{"n":1},{"n":2}]`)
		case "2":
			_, _ = io.WriteString(w, `[{"n":3}]`)
		}
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	var got []struct{ N int }
	if err := c.GetAll(context.Background(), "/items", &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].N != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestDoWaitsOutRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	var out struct{ OK bool }
	if _, err := c.Do(context.Background(), http.MethodGet, "/x", nil, &out); err != nil || !out.OK {
		t.Fatalf("err %v out %+v calls %d", err, out, calls)
	}
}

func TestPermissionErrorsAreRecognised(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	_, err := c.Do(context.Background(), http.MethodPost, "/x", map[string]string{"a": "b"}, nil)
	if !IsPermission(err) {
		t.Fatalf("want a permission error, got %v", err)
	}
}

func TestUploadSARIFAndWait(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repos/o/r/code-scanning/sarifs":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["commit_sha"] != "abc" || body["ref"] != "refs/heads/main" {
				t.Errorf("body %+v", body)
			}
			raw, _ := base64.StdEncoding.DecodeString(body["sarif"])
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			doc, _ := io.ReadAll(zr)
			if string(doc) != `{"version":"2.1.0"}` {
				t.Errorf("sarif %s", doc)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"id":"u1","url":"x"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/o/r/code-scanning/sarifs/u1":
			polls++
			if polls < 2 {
				_, _ = io.WriteString(w, `{"processing_status":"pending"}`)
				return
			}
			_, _ = io.WriteString(w, `{"processing_status":"complete"}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	c := NewClient("tok")
	c.BaseURL = srv.URL
	tg := Target{Repo: "o/r", SHA: "abc", Ref: "refs/heads/main"}
	up, err := c.UploadSARIF(context.Background(), tg, []byte(`{"version":"2.1.0"}`), "")
	if err != nil || up.ID != "u1" {
		t.Fatalf("upload %+v %v", up, err)
	}
	st, err := c.WaitSARIF(context.Background(), "o/r", "u1", 5*time.Second, time.Millisecond)
	if err != nil || st.ProcessingStatus != "complete" {
		t.Fatalf("wait %+v %v", st, err)
	}
}

func TestResolveTarget(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "o/r")
	t.Setenv("GITHUB_SHA", "abc")
	t.Setenv("GITHUB_REF", "refs/pull/7/merge")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	tg, err := ResolveTarget(t.TempDir(), "", "", "")
	if err != nil || tg.Repo != "o/r" || tg.SHA != "abc" || tg.Ref != "refs/pull/7/merge" {
		t.Fatalf("%+v %v", tg, err)
	}
	tg, err = ResolveTarget(t.TempDir(), "x/y", "def", "main")
	if err != nil || tg.Repo != "x/y" || tg.Ref != "refs/heads/main" || tg.Owner() != "x" || tg.Name() != "y" {
		t.Fatalf("explicit %+v %v", tg, err)
	}
}

func TestRepoFromRemote(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/Vulnetix/cli.git":         "Vulnetix/cli",
		"https://x-access-token:s@github.com/a/b":     "a/b",
		"git@github.com:Vulnetix/cli.git":             "Vulnetix/cli",
		"ssh://git@github.example.com/team/repo.git/": "team/repo",
		"not a url":                                   "",
	} {
		if got := RepoFromRemote(in); got != want {
			t.Errorf("RepoFromRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
