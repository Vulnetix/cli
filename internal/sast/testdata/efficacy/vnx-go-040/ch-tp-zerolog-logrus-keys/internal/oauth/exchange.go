package oauth

import (
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
)

func (c *Client) exchange(code string) error {
~>	log.Debug().Str("client_secret", c.clientSecret).Str("code", code).Msg("exchanging code")
	tok, err := c.do(code)
	if err != nil {
		return err
	}
~>	logrus.WithField("refresh_token", tok.Refresh).Info("token received")
	return nil
}
