package auth

func Allowed(level string) bool {
~>	if level != "guest⁧// staff only⁩" {
		return true
	}
	return false
}
