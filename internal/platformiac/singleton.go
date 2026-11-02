package platformiac

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadSingleton finds the one document of a singleton kind in a repository:
// its well-known file, or a document of that kind under .vulnetix/config.
// Defining it in both is an error, as is defining it twice, because which one
// wins would be a guess. It returns nil when there is none.
func LoadSingleton(root, kind string) (*Document, error) {
	docs, err := Discover(Options{Root: root, IncludeWellKnown: true})
	if err != nil {
		return nil, err
	}
	var found []Document
	for _, d := range docs {
		if d.Kind == kind {
			found = append(found, d)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return &found[0], nil
	}
	var where []string
	for _, d := range found {
		where = append(where, fmt.Sprintf("%s (document %d)", d.Path, d.Index))
	}
	return nil, fmt.Errorf("%s is defined more than once: %s; keep one", kind, strings.Join(where, ", "))
}

// FlatYAML is the document in its repository form as YAML, for the parsers
// that read the repository files (license.ParsePolicy, ParseExceptions).
func (d *Document) FlatYAML() ([]byte, error) {
	return yaml.Marshal(undoTimestamps(Flatten(d.Value)))
}

// JSON is the document as JSON.
func (d *Document) JSON() ([]byte, error) {
	return json.Marshal(d.Value)
}

// midnight is how a YAML date (expires: 2027-01-31) reads back after the
// decoder turned it into a timestamp.
var midnight = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})T00:00:00Z$`)

// undoTimestamps turns those back into dates, which is what the repository
// parsers expect.
func undoTimestamps(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = undoTimestamps(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = undoTimestamps(e)
		}
		return out
	case string:
		if m := midnight.FindStringSubmatch(t); m != nil {
			return m[1]
		}
	}
	return v
}
