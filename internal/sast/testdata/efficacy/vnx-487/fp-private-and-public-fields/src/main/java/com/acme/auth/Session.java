package com.acme.auth;

public class Session {
    private String apiToken;
    private final char[] password;
    public String tokenType;
    protected byte[] secret;
    int retries;
    String displayName;

    Session(char[] password) {
        this.password = password;
    }
}
