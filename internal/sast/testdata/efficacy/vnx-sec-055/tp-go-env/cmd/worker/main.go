package main

import "github.com/newrelic/go-agent/v3/newrelic"

func main() {
	app, _ := newrelic.NewApplication(
		newrelic.ConfigAppName("worker"),
~>		newrelic.ConfigLicense("@@sample:[a-f0-9]{36}@@NRAL"),
	)
	_ = app
}
