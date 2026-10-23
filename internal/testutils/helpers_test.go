package testutils

import (
	"errors"
	"reflect"
	"testing"
)

func TestGetEnvMapFromStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  map[string]string
	}{
		{
			name:  "plain key value",
			input: []string{"A=B"},
			want:  map[string]string{"A": "B"},
		},
		{
			name:  "empty value",
			input: []string{"A="},
			want:  map[string]string{"A": ""},
		},
		{
			name:  "bare key",
			input: []string{"A"},
			want:  map[string]string{"A": ""},
		},
		{
			name:  "value containing equals",
			input: []string{"A=B=C"},
			want:  map[string]string{"A": "B=C"},
		},
		{
			name:  "last wins",
			input: []string{"A=B", "A=C"},
			want:  map[string]string{"A": "C"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetEnvMapFromStrings(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("GetEnvMapFromStrings(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAssertHelpers(t *testing.T) {
	t.Run("AssertNoError nil", func(t *testing.T) {
		AssertNoError(t, nil)
	})

	t.Run("AssertError matching message", func(t *testing.T) {
		AssertError(t, errors.New("boom: nope"), "boom")
	})
}
