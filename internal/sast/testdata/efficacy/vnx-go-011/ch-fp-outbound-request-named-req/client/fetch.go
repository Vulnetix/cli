package client

import (
	"context"
	"encoding/gob"
	"net/http"
)

type Catalog struct{ Names []string }

func Fetch(ctx context.Context, hc *http.Client, url string) (*Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/x-gob")
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var c Catalog
	if err := gob.NewDecoder(res.Body).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
