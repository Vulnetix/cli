package num

import (
	"net"
	"strconv"
)

func Dec(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
func Hex(s string) (uint64, error) { return strconv.ParseUint(s, 16, 32) }
func IP(s string) net.IP          { return net.ParseIP(s) }
