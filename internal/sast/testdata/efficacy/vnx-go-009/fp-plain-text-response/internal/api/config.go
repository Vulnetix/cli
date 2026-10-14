package api

import (
	"net/http"
	"text/template"
)

var envFile = template.Must(template.New("env").Parse("REGION={{.Region}}\nBUCKET={{.Bucket}}\n"))

var unitFile = template.Must(template.New("unit").Parse("[Service]\nExecStart={{.Cmd}}\n"))

// DownloadEnv serves a dotenv file. The explicit non-HTML content type means
// a browser never parses the response as markup.
func DownloadEnv(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	envFile.Execute(w, map[string]string{"Region": "eu-west-1", "Bucket": r.URL.Query().Get("bucket")})
}

func Unit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	unitFile.Execute(w, map[string]string{"Cmd": "/usr/bin/agent"})
}
