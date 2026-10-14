package cache

import (
	"context"
	"net/http"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	rdb   *redis.Client
	local map[string]string
}

// Get on a cache or map is a lookup, not an outbound request.
func (s *Store) Lookup(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	v, _ := s.rdb.Get(context.Background(), key).Result()
	if v == "" {
		v = s.local[key]
	}
	w.Write([]byte(v))
}

// Never call http.Get(r.FormValue("url")) without an allowlist.
const advice = `resp, err := http.Get(r.FormValue("url"))`
