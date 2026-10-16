import os

STORAGE_ACCOUNT = os.environ["AZURE_STORAGE_ACCOUNT"]
AZURE_STORAGE_KEY = os.environ["AZURE_STORAGE_KEY"]
CONN = f"DefaultEndpointsProtocol=https;AccountName={STORAGE_ACCOUNT};AccountKey={AZURE_STORAGE_KEY};EndpointSuffix=core.windows.net"
