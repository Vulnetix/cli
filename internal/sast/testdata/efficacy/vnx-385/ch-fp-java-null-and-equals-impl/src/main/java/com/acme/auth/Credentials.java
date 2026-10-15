package com.acme.auth;

import java.security.MessageDigest;
import java.util.Objects;

public class Credentials {
    private String username;
    private String password;

    public boolean isMissing() {
        return password == null || password.isEmpty();
    }

    public boolean sameAs(byte[] expected, byte[] actualPasswordHash) {
        return MessageDigest.isEqual(expected, actualPasswordHash);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Credentials)) return false;
        Credentials that = (Credentials) o;
        return Objects.equals(username, that.username) && Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, password);
    }
}
