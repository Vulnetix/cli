package web

import (
	"fmt"
	"html/template"
	"net/http"
	"os/exec"
)

// The parameter passes through one intermediate variable before the sink.
func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	script := "ping -c 1 " + host
~>	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func Lookup(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	notFound := fmt.Sprintf("<b>%s</b> not found", term)
	data := map[string]any{}
~>	data["msg"] = template.HTML(notFound)
	msg := "<p>" + term + "</p>"
~>	w.Write([]byte(msg))
}
