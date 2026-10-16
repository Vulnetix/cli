import os

import psycopg2

# Connection details for the reporting warehouse.
~># password = "Wareh0use!2024"
# host = "warehouse.internal"


def connect():
    return psycopg2.connect(
        host=os.environ["WH_HOST"],
        user="etl",
~>        password=os.environ["WH_PASSWORD"],  # old password: Pr0d#Etl2023
    )


def legacy_export(client):
~>    # client_secret=9f3a77c2be41d0e8 (staging app, ask ops before removing)
    return client.export(format="parquet")
