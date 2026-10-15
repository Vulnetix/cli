package com.acme.crypto;

public class KeyHolder {
    private byte[] secretKey;
    private String[] roles;

    public byte[] getSecretKey() {
        return secretKey.clone();
    }

    public String[] getRoles() {
        return Arrays.copyOf(roles, roles.length);
    }

    public List<String> roleList() {
        return List.of(roles);
    }
}
