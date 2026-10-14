from pydo import Client

client = Client(
~>    token='dop_v1_@@sample:[a-f0-9]{64}@@'
)
print(client.droplets.list())
