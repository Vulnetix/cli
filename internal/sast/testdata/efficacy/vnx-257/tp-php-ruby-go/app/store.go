package app

func save(u *User, password string) {
~>	u.Secret = @@sample:b[a]se[6]4[.][S]td[E]nc[o]di[n]g[.][E]nc[o]de[T]oS[t]ri[n]g@@([]byte(password))
~>	sealed := gcm.Seal(nil, nonce, []byte(u.Password), nil)
	_ = sealed
}
