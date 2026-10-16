package auth

func Login(hash []byte, pw string) bool {
	if err := bcrypt.CompareHashAndPassword(hash, []byte(pw)); err != nil {
		return false
	}
	return true
}
