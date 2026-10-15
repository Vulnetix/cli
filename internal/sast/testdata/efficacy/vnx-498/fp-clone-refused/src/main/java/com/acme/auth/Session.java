package com.acme.auth;

public class Session extends Base implements Cloneable {
    private String sessionToken;

    @Override
    protected final Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }
}
