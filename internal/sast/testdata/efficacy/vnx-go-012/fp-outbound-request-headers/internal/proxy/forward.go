package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Forward builds an upstream request; these are request headers, and the
// client refuses to send a value containing CR or LF.
func Forward(w http.ResponseWriter, r *http.Request, upstream string) (*http.Response, error) {
	out, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	if err != nil {
		return nil, err
	}
	out.Header.Set("Accept-Language", r.URL.Query().Get("lang"))
	out.Header.Add("X-Tenant", r.FormValue("tenant"))
	return http.DefaultClient.Do(out)
}

// gin's c.Set stores a context value; it is not a header.
func Remember(c *gin.Context) {
	c.Set("theme", c.Query("theme"))
	c.Next()
}
