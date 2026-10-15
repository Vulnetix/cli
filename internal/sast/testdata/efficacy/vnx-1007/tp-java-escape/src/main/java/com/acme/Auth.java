package com.acme;

public class Auth {
~>    private static final String SUPERUSER = "аdmin";
~>    private static final String OPERATOR = "Οperator";

    public boolean isSuper(String user) {
        return SUPERUSER.equals(user);
    }
}
