package cfg

import "strconv"

type Listener struct {
	port uint16
}

func ParsePort(s string) (int, bool) {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return port, port >= 0 && port < 65536
}
