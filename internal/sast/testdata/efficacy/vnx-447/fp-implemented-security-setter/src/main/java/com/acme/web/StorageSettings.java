package com.acme.web;

public class StorageSettings {
    private boolean encryption;

    public void setEncryptionEnabled(boolean enabled) {
        this.encryption = enabled;
    }

    public boolean changePassword(String user, String oldPassword, String newPassword) {
        return store.update(user, encoder.encode(newPassword));
    }
}
