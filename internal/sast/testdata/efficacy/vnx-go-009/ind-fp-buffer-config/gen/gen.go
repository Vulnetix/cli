package gen

import (
	"bytes"
	"os"
	"text/template"
)

// Uses text/template to generate YAML, not an HTML page.
var cfg = template.Must(template.New("cfg").Parse("name: {{.Name}}\nreplicas: {{.N}}\n"))

func Write(path string, name string, n int) error {
	var buf bytes.Buffer
	if err := cfg.Execute(&buf, map[string]any{"Name": name, "N": n}); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
