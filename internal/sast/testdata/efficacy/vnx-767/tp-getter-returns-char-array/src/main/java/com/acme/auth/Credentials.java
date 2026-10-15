package com.acme.auth;

public class Credentials {
    private final String user;
    private char[] password;

    public Credentials(String user, char[] password) {
        this.user = user;
        this.password = password;
    }

    public String getUser() { return user; }

~>    public char[] getPassword() { return password; }
}
