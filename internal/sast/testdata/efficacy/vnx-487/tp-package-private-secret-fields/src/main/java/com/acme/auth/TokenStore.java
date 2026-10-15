package com.acme.auth;

public class TokenStore {
~>    String apiToken;
~>    char[] masterPassword;
~>    byte[] signingSecret = loadSecret();
    private int size;
    protected String name;

    void put(String t) {
        apiToken = t;
    }
}
