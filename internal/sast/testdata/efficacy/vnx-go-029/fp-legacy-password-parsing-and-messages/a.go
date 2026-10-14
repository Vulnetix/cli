package a

func f(tokens []string, j int) (password string) {
	password = tokens[j+1]
	return fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", a, b, c)
}

var awsResourceIDRe = regexp.MustCompile("^(?:ami|snap|sg|fs|lt)-[0-9a-f]+$")
var words = []string{"password", "token"}
