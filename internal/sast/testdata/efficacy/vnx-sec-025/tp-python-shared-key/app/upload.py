from azure.storage.blob import BlobServiceClient
from azure.storage.blob import StorageSharedKeyCredential

credential = StorageSharedKeyCredential(
    "contosodata",
~>    "@@sample:[A-Za-z0-9+/]{86}@@==",
)
client = BlobServiceClient("https://contosodata.blob.core.windows.net", credential=credential)
