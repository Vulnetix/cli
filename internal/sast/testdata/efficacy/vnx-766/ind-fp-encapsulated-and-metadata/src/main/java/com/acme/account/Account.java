package com.acme.account;

import java.time.Instant;

public class Account {
    private String password;
    protected String apiKey;
    String refreshToken;
    public boolean passwordExpired;
    public int tokenCount;
    public String passwordHint;
    public String tokenUrl;
    public String tokenType = "Bearer";
    public Instant passwordChangedAt;
    public String displayName;

    public void changePassword(String newHash) {
        String password = newHash;
        this.password = password;
        this.passwordChangedAt = Instant.now();
    }
}
