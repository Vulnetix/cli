import os, hvac
client = hvac.Client(token=os.environ["VAULT_TOKEN"])
