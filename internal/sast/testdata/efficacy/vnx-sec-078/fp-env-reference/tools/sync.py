import os
TOKEN = os.environ["DOPPLER_TOKEN"]
assert TOKEN.startswith("dp.pt.")
