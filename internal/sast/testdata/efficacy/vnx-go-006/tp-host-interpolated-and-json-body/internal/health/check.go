package health

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Status(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
~>	resp, err := http.Get("http://" + host + "/status")
	if err == nil {
		resp.Body.Close()
	}
	port := r.URL.Query().Get("port")
	u := fmt.Sprintf("http://%s:%s/healthz", host, port)
~>	if resp, err := http.Get(u); err == nil {
		resp.Body.Close()
	}
}

// "https://api.example.com" + "@evil.example" is a request to evil.example.
func Region(w http.ResponseWriter, r *http.Request) {
	region := r.FormValue("region")
~>	resp, err := http.Get("https://api." + region + ".example.com/v1/ping")
	if err == nil {
		resp.Body.Close()
	}
}

type hook struct {
	URL   string `json:"url"`
	Event string `json:"event"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	var in hook
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(map[string]string{"event": in.Event})
~>	resp, err := http.Post(in.URL, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func RegisterGin(c *gin.Context) {
	var req struct {
		Callback string `json:"callback"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
~>	resp, err := http.Get(req.Callback)
	if err == nil {
		resp.Body.Close()
	}
}
