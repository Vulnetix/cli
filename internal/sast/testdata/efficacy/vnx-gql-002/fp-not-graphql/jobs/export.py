from app.db import session
from app.exporter import Exporter


def run():
    exporter = Exporter(session, batch=True, size=500)
    exporter.write("out.csv")
