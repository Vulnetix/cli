import psycopg2


def connect(host, port=5432, dbname="app", ssl=False, use_tls=False, items=[]):
    sslmode = "require" if ssl or use_tls else "prefer"
    return psycopg2.connect(host=host, port=port, dbname=dbname, sslmode=sslmode)
