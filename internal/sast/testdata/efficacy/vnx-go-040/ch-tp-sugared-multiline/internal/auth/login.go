package auth

import "go.uber.org/zap"

func (s *Service) Login(user, pw string) error {
~>	s.log.Infow("login attempt",
		"user", user,
		"password", pw,
	)
	return s.check(user, pw)
}
