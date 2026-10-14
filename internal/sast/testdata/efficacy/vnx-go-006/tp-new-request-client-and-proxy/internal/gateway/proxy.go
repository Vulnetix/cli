package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

func Forward(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("dest")
~>	req, err := http.NewRequest("GET", dest, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func Feed(c *gin.Context) {
	endpoint := c.Query("feed")
~>	req, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, endpoint, nil)
	_, _ = httpClient.Do(req)
~>	_, _ = httpClient.Get(c.Query("mirror"))
}

// url.Parse checks syntax, not the destination.
func Upstream(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(r.URL.Query().Get("upstream"))
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadRequest)
		return
	}
~>	httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
}

func Port(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("addr")
~>	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		conn.Close()
	}
}
