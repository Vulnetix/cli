package browse

import (
	"io/ioutil"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

type Handler struct{ root string }

func (h *Handler) Doc(w http.ResponseWriter, r *http.Request) {
~>	data, err := os.ReadFile(
		filepath.Join(
			h.root,
			r.URL.Query().Get("doc"),
		),
	)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func (h *Handler) List(c *gin.Context) {
~>	entries, err := ioutil.ReadDir(h.root + "/" + c.Param("sub"))
	if err != nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, len(entries))
}
