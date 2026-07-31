package vdb

import "testing"

func TestFormatAPIError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{
			// The shape the auth probe hit: an error with no details rendered a
			// dangling separator ("Cannot query future months - ").
			name:   "error without details omits the separator",
			status: 400,
			body:   `{"success":false,"error":"Cannot query future months"}`,
			want:   "API error (400): Cannot query future months",
		},
		{
			name:   "error with details keeps both",
			status: 403,
			body:   `{"success":false,"error":"Forbidden","details":"plan required"}`,
			want:   "API error (403): Forbidden - plan required",
		},
		{
			// Any JSON object unmarshals into ErrorResponse without error, so
			// guarding only on the unmarshal produced an empty message.
			name:   "unrelated JSON falls back to the raw body",
			status: 500,
			body:   `{"message":"boom"}`,
			want:   `API error (500): {"message":"boom"}`,
		},
		{
			name:   "non-JSON falls back to the raw body",
			status: 502,
			body:   "<html>bad gateway</html>",
			want:   "API error (502): <html>bad gateway</html>",
		},
		{
			name:   "empty body",
			status: 401,
			body:   "",
			want:   "API error (401): ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatAPIError(tc.status, []byte(tc.body)); got != tc.want {
				t.Errorf("formatAPIError() = %q, want %q", got, tc.want)
			}
		})
	}
}
