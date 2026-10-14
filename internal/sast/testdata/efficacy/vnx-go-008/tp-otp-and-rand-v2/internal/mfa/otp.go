package mfa

import (
	"fmt"
	mrand "math/rand/v2"
)

func (m *Manager) Send(user string) error {
~>	otp := fmt.Sprintf("%06d", mrand.IntN(1000000))
	return m.sms.Deliver(user, otp)
}

func (m *Manager) challenge() uint64 {
~>	nonce := mrand.Uint64()
	m.pending[nonce] = true
	return nonce
}
