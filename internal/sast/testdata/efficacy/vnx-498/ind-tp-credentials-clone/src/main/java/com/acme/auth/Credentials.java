package com.acme.auth;

import java.util.Arrays;

~>public class Credentials implements Cloneable {
    private String username;
    private char[] password;

    public Credentials(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public Credentials clone() {
        try {
            Credentials c = (Credentials) super.clone();
            c.password = Arrays.copyOf(password, password.length);
            return c;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
