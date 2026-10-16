import psycopg2

~>DB_PASSWORD = "postgres"

def conn():
~>    return psycopg2.connect(host="db", user="app", password="password")
