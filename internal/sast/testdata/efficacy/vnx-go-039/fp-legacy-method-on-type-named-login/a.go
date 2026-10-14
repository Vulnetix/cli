package a

func (l Login) Encode() string { return "" }
func ParseLogin(s string) (Login, error) { return Login{}, nil }
func importCLI(home string) (Login, string, error) { return Login{}, "", nil }
