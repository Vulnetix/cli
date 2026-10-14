package lint

// Do not ship InsecureSkipVerify: true; load the CA into RootCAs instead.
const hint = "found InsecureSkipVerify: true in tls.Config"

var example = `cfg.InsecureSkipVerify = true`

func Messages() []string { return []string{hint, example} }
