import redis, pika, ldap3

r = redis.from_url("rediss://:pw@cache.prod.acmecorp.net:6380/0")
p = pika.URLParameters("amqps://svc:pw@mq.prod.acmecorp.net:5671/")
s = ldap3.Server("ldaps://ldap.corp.acmecorp.io:636")
sftp_target = "sftp://deploy@files.acmecorp.net/releases"
ftps_target = "ftps://files.acmecorp.net/releases"
