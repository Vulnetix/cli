package auth

import "errors"

var ErrBadCredentials = errors.New("invalid username or password")

func (s *Service) Login(email, password string) error {
	u, err := s.users.ByEmail(email)
	if err != nil {
		return ErrBadCredentials
	}
	if !s.verify(u, password) {
		return ErrBadCredentials
	}
	return nil
}
