package svc

import "github.com/rs/zerolog/log"

func load(signingSecret string) {
~>	log.Debug().Str("secret", signingSecret).Msg("loaded")
}
