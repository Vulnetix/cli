package com.acme.kdf;

public class Salted {
    private byte[] salt;
    private String[] scopes;

    public byte[] getSalt() {
        return salt.clone();
    }

    public String[] getScopes() {
        return Arrays.copyOf(scopes, scopes.length);
    }

    public List<String> scopeList() {
        return Collections.unmodifiableList(Arrays.asList(scopes));
    }
}
