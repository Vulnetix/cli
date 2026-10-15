import os

REDIS_URL = "rediss://default:h4Ty8LpQ2wZx@@@sample:r[e]di[s][.]p[r]od[.]ac[m]ec[o]rp[.]ne[t]@@:6380/0"
BROKER_URL = "amqps://celery:Wq7rT2pZ@@@sample:r[a]bb[i]t[.][p]ro[d][.]a[c]me[c]or[p][.]n[e]t@@:5671//"
LDAP_URI = "ldaps://ldap.corp.acmecorp.io:636"
FILES = "sftp://files.vendordata.com/export"
CACHE = f"redis://{os.environ['REDIS_HOST']}:6379/0"
QUEUE = "amqp://" + os.environ["RABBIT_HOST"] + ":5672"
LOCAL = "redis://localhost:6379"
LOOP = "amqp://guest:guest@127.0.0.1:5672/"
EXAMPLE = "ftp://ftp.example.com/pub"
