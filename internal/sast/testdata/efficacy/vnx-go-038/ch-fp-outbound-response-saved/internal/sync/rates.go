package sync

import (
	"context"
	"encoding/json"
	"net/http"
)

func (s *Syncer) Pull(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream+"/rates", nil)
	if err != nil {
		return err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var rates []Rate
	if err := json.NewDecoder(res.Body).Decode(&rates); err != nil {
		return err
	}
	return s.db.Create(&rates).Error
}
