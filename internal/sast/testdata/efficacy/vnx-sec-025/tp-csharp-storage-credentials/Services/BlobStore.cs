using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Auth;

public class BlobStore
{
    public CloudStorageAccount Open()
    {
~>        var creds = new StorageCredentials("contosodata", "@@sample:[A-Za-z0-9+/]{86}@@==");
        return new CloudStorageAccount(creds, true);
    }
}
