package site

import (
	"html/template"
	"net/http"
	"os"
	texttemplate "text/template"
)

// The page is html/template; text/template only renders the robots.txt file
// written to disk at startup.
var page = template.Must(template.New("p").Parse(`<p>{{.}}</p>`))

var robots = texttemplate.Must(texttemplate.New("robots").Parse("User-agent: *\nDisallow: {{.}}\n"))

func Page(w http.ResponseWriter, r *http.Request) {
	page.Execute(w, r.URL.Query().Get("msg"))
}

func WriteRobots(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return robots.Execute(f, "/admin")
}
