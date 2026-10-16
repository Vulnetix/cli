import psycopg2

def sample():
    return psycopg2.connect(host="db.example.com", dbname="demo")

def short():
    return psycopg2.connect(host="db", dbname="demo")
