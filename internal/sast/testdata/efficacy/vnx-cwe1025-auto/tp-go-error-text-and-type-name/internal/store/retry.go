package store

import (
	"fmt"
	"reflect"
)

func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
~>	if err.Error() == "connection reset by peer" {
		return true
	}
~>	return "context deadline exceeded" == err.Error()
}

func isClosed(err error) bool {
	msg := err.Error()
~>	if msg == "use of closed network connection" {
		return true
	}
	return false
}

func isAdminPrincipal(p interface{}) bool {
~>	if reflect.TypeOf(p).Name() == "AdminPrincipal" {
		return true
	}
~>	return fmt.Sprintf("%T", p) == "*auth.AdminPrincipal"
}
