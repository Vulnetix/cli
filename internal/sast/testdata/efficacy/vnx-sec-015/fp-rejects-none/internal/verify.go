package internal

func keyFunc(t *jwt.Token) (interface{}, error) {
	if t.Method == jwt.SigningMethodNone {
		return nil, errors.New("unsigned token")
	}
	return key, nil
}
