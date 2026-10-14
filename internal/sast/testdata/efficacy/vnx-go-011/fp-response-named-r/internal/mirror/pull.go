package mirror

import (
	"encoding/gob"
	"net/http"
)

type Index struct{ Entries []string }

// Pull fetches the index from the configured primary; r is the response.
func Pull(primary string) (Index, error) {
	var idx Index
	r, err := http.Get(primary + "/index.gob")
	if err != nil {
		return idx, err
	}
	defer r.Body.Close()
	return idx, gob.NewDecoder(r.Body).Decode(&idx)
}

func PullWith(c *http.Client, req *http.Request) (Index, error) {
	var idx Index
	resp, err := c.Do(req)
	if err != nil {
		return idx, err
	}
	defer resp.Body.Close()
	err = gob.NewDecoder(resp.Request.Body).Decode(&idx)
	return idx, err
}
