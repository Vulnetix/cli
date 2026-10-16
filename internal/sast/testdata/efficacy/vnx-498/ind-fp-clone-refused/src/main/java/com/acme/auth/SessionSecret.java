package com.acme.auth;

public class SessionSecret extends BaseToken implements Cloneable {
    private String sessionToken;
    private char[] passphrase;

    @Override
    protected final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("SessionSecret must not be copied");
    }
}
