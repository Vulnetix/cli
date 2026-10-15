package com.acme.model;

public class Account {
    private String passwordHash;

    public String getPassword() {
        return passwordHash;
    }

    public String describe() {
        // never do new String(field.getPassword()) for a JPasswordField
        String hash = String.valueOf(getPassword());
        return "Account[" + hash.length() + "]";
    }
}
