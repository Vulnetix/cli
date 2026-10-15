package com.acme.auth;

import java.io.Serializable;
import javax.crypto.SecretKey;

~>public final class Credentials implements
        Serializable, Cloneable {

    private final String username;
    private char[] passphrase;

    public Credentials(String username, char[] passphrase) {
        this.username = username;
        this.passphrase = passphrase;
    }

    @Override
    public Credentials clone() {
        try {
            return (Credentials) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

~>    static class Session implements Cloneable {
        String sessionToken;
        long expiresAt;
    }
}
