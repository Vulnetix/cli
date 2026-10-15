package com.acme.auth;

public class Login {
    private char[] password;

    String[] fields() {
        return new String[] { "user", String.valueOf(password.length) };
    }

    Object[] args() {
        Object[] a = new Object[] {
            password,
            "x"
        };
        return a;
    }
}
