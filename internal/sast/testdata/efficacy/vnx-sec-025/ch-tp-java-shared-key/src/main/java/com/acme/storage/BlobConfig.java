package com.acme.storage;

import com.azure.storage.common.StorageSharedKeyCredential;

public class BlobConfig {
    public StorageSharedKeyCredential credential() {
~>        return new StorageSharedKeyCredential("acmeprod", "@@sample:[A-Za-z0-9+/]{86}@@==");
    }
}
