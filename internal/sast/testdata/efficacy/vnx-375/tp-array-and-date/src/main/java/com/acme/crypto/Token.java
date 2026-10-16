package com.acme.crypto;

import java.util.Date;

public final class Token {
    private final byte[] secret;
    private final Date expires;
    private static final String[] SCOPES = {"read", "write"};

    public Token(byte[] secret, Date expires) {
        this.secret = secret.clone();
        this.expires = new Date(expires.getTime());
    }

    public byte[] getSecret() {
        return secret;
    }

    public Date getExpires() {
~>        return this.expires;
    }

    protected String[] scopes() {
~>        return SCOPES;
    }
}
