package auth

import (
	"log"
	"log/slog"
	"time"

	"go.uber.org/zap"
)

func (s *Store) refresh(tokens []string, ttl time.Duration, apiKey string) {
	log.Printf("refreshing %d tokens", len(tokens))
	s.zl.Info("refreshed", zap.Duration("token_ttl", ttl), zap.Int("token_count", len(tokens)))
	slog.Info("upstream configured", "has_api_key", apiKey != "")
	if apiKey == "" {
		log.Println("api key missing; set API_KEY")
	}
}
