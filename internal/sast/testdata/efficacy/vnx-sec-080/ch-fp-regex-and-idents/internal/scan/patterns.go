package scan

var githubToken = `gh[pousr]_[A-Za-z0-9]{36}`

type Config struct {
	ghs_token_ttl int
	@@sample:g[h]o[_]scopes@@    []string
}
