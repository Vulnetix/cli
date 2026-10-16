import os
import socket
# fallback was 10.1.2.3 in the old deployment
ALLOWED_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
DB_HOST = os.environ.get("DB_HOST", "localhost")
LOCAL = "127.0.0.1"
BIND = "0.0.0.0"
DOC = "http://203.0.113.10/example"
DOC2 = "198.51.100.7"
META = "http://169.254.169.254/latest/meta-data/"
SNMP_OID = "1.3.6.1.4.1.9"
VERSION = "10.2.4.1"
s = socket.create_connection(("db.internal.example.com", 5432))
API = "https://api.example.com/v1"
