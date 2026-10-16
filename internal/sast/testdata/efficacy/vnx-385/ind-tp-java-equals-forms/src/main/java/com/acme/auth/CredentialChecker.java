package com.acme.auth;

import java.util.Arrays;
import java.util.Objects;

public class CredentialChecker {
    private final UserStore store;

    public CredentialChecker(UserStore store) {
        this.store = store;
    }

    public boolean check(String name, String candidate) {
        UserRecord u = store.find(name);
        String encoded = Hashing.sha256Hex(candidate, u.salt());
~>        return u != null && u.getPasswd().equals(encoded);
    }

    public boolean checkBytes(String name, char[] candidate) {
        UserRecord u = store.find(name);
        byte[] computed = Hashing.pbkdf2(candidate, u.salt());
~>        return Arrays.equals(u.getPasswordHash(), computed);
    }

    public boolean checkObjects(UserRecord u, String hashed) {
~>        return Objects.equals(u.passwordHash(), hashed);
    }

    public boolean checkWrapped(UserRecord u, String encoded) {
~>        return u.getPassword()
                .equals(encoded);
    }
}
