import os

HOST = os.environ["DB_ADDR"].split(":")[0]
PORT = int(os.environ["DB_ADDR"].split(":")[1])
