package reset

import "github.com/google/uuid"

func Token() (string, error) {
~>	u, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	resetToken := u.String()
	return resetToken, nil
}
