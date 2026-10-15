import os
import ldap

~>AUTH_LDAP_SERVER_URI = "ldap://ldap.corp.acmecorp.io:389"
~>@@sample:C[E]LE[R]Y[_][B]RO[K]ER[_]UR[L]@@ = 'amqp://celery:Wq7rT2pZ@@@sample:r[a]bb[i]t[.][p]ro[d][.]a[c]me[c]or[p][.]n[e]t@@:5672//'

def connect():
~>    conn = ldap.initialize("ldap://10.20.30.40")
    return conn
