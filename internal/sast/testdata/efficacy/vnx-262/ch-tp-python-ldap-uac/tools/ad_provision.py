from ldap3 import MODIFY_REPLACE

NORMAL_ACCOUNT = 0x0200
DONT_EXPIRE_PASSWD = 0x10000


def enable_service_account(conn, dn):
~>    conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [NORMAL_ACCOUNT | DONT_EXPIRE_PASSWD])]})


def enable_robot(conn, dn):
~>    conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [66048])]})
