package a

func f(tokens []string, j int, t *testing.T) {
	password = tokens[j+1]
	t.Fatalf("password = %q", password)
	cfg := "  password: " + yamlString(opts.APIKey)
	doc := "import os\npassword = os.environ['PW']\n"
}
