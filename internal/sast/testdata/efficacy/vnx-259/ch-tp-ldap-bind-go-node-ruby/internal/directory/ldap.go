package directory

import "github.com/go-ldap/ldap/v3"

func Connect(addr string) (*ldap.Conn, error) {
	l, err := ldap.DialURL(addr)
	if err != nil {
		return nil, err
	}
~>	if err := l.Bind("cn=svc-portal,ou=services,dc=example,dc=com", "P0rtalB1nd!"); err != nil {
		return nil, err
	}
	return l, nil
}
