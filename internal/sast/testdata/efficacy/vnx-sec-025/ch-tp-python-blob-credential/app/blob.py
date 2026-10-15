from azure.storage.blob import BlobServiceClient

client = BlobServiceClient(
    account_url="https://acmeexports.blob.core.windows.net",
~>    credential="@@sample:[A-Za-z0-9+/]{86}@@==",
)
