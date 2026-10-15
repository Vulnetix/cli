package com.acme.web;

public class StorageSettings {
    private String bucket;

    public void setBucket(String bucket) {
        this.bucket = bucket;
    }

~>    public void setEncryptionEnabled(boolean enabled) {
        // TODO: wire this to the storage client
    }

~>    public void enableAuditLogging(boolean on) { }
}
