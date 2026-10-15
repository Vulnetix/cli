import os

# connection for the reporting replica
~># password = "R3port!ng2023"
DB_PASSWORD = os.environ["DB_PASSWORD"]

def connect():
~>    # TODO remove: db_pass=Kx9#mQ2vL
    return open_conn(DB_PASSWORD)
