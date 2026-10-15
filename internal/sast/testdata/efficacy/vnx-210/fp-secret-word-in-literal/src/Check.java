package com.shop;

public class Check {
    public void check(String password) {
        if (password == null) {
            throw new IllegalArgumentException("password must not be null");
        }
        if (password.length() < 12) {
            throw new IllegalArgumentException("password too short: " + password.length());
        }
    }
}
