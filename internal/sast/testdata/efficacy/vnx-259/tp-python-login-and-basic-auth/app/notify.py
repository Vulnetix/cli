import smtplib
import requests
from requests.auth import HTTPBasicAuth


def send(msg):
    server = smtplib.SMTP("smtp.example.org", 587)
~>    server.login("alerts@example.org", "Wint3r-Is-Coming")
~>    requests.get(URL, auth=HTTPBasicAuth('api', 'S3cr3t!pass'))
~>    requests.post(URL, auth=("svc", "hunter2-prod"), json=msg)
~>    db = pymysql.connect("db.internal", "app", "Tr0ub4dor&3", "shop")
~>    conn.simple_bind_s("cn=admin,dc=example,dc=org", 'ldap-Adm1n')
