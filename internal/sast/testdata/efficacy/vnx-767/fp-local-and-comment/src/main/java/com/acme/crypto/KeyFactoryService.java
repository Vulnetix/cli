package com.acme.crypto;

public class KeyFactoryService {
    // public char[] getPassword() { return password; }

    public String getPrivateKey(String id) {
        String privateKey = load(id);
        return privateKey;
    }

    public String getSecretName() {
        return "app-secret";
    }

    private String load(String id) { return id; }
}
