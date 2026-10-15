package com.acme.auth;

~>public class Credentials implements Cloneable {
    private String username;
    private char[] password;

    @Override
    public Credentials clone() throws CloneNotSupportedException {
        return (Credentials) super.clone();
    }
}
