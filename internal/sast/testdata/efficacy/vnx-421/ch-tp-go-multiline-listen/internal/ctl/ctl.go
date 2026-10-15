package ctl

import "net"

func Listen() (net.Listener, error) {
~>	return net.Listen(
		"unix",
		"/tmp/ctl.sock",
	)
}
