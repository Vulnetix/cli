# LDAP

An anonymous `ldap_bind($conn);` or `ldap_bind($conn, $dn, '');` succeeds
on most servers without checking anything. Always reject an empty password.
