from azure.storage.blob import BlobServiceClient

client = BlobServiceClient(
    account_url="https://contosodata.blob.core.windows.net",
    credential=StorageSharedKeyCredential(
        "contosodata",
~>        "@@sample:[A-Za-z0-9+/]{86}==@@",
    ),
)
