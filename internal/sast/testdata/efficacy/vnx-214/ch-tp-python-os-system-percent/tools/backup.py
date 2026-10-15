import os


def dump(user, pw, db, out):
~>    os.system("mysqldump -u %s -p%s %s > %s" % (user, pw, db, out))
