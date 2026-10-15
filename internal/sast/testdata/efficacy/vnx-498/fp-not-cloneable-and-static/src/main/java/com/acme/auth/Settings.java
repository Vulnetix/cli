package com.acme.auth;

// A Cloneable class holding a password would be a problem: class X implements Cloneable
public class Settings {
    private static final String PASSWORD_KEY = "password";
    private String password;
}
