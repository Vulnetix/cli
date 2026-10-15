package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type Server struct{ etcdClient *clientv3.Client }

func (s *Server) Key(w http.ResponseWriter, r *http.Request) {
	resp, err := s.etcdClient.Get(r.Context(), r.FormValue("key"))
	if err != nil || len(resp.Kvs) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Write(resp.Kvs[0].Value)
}

func Profile(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{"user": user, "hint": "never call http.Get(c.Query(\"url\")) here"})
}
