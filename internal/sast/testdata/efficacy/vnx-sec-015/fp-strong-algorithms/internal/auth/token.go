package auth

func Issue(claims jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claims)
	return t.SignedString(secret)
}
