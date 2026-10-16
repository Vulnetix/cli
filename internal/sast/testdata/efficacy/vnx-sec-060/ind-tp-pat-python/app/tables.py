from pyairtable import Api

api = Api(
~>    "pat@@sample:[A-Za-z0-9]{14}@@.@@sample:[a-f0-9]{64}@@"
)
table = api.table("appXXXXXXXXXXXXXX", "Tasks")
