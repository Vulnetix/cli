package notify

import (
	"bytes"
	"html/template"
	"net/http"
	ttemplate "text/template"
)

// The plain-text part of the email is rendered with text/template; the
// browser-facing preview uses html/template. text/template's Execute(w, ...)
// is not used for HTML anywhere here.
var plainBody = ttemplate.Must(ttemplate.ParseFiles("mail/welcome.txt.tmpl"))

var preview = template.Must(template.New("preview").Parse(`<pre>{{.}}</pre>`))

func Render(name string) (string, error) {
	var buf bytes.Buffer
	if err := plainBody.Execute(&buf, map[string]string{"Name": name}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Preview(w http.ResponseWriter, r *http.Request) {
	body, err := Render(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	preview.Execute(w, body)
}
