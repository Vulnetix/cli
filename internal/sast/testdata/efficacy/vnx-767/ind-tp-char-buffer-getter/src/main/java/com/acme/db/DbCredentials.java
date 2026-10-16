package com.acme.db;

import java.util.Arrays;

public class DbCredentials {
    private final String user;
    private char[] password;

    public DbCredentials(String user, char[] password) {
        this.user = user;
        this.password = password;
    }

    public String getUser() {
        return user;
    }

~>    public char[] getPassword() { return password; }

    public void wipe() {
        Arrays.fill(password, '\0');
    }
}
