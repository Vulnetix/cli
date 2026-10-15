package com.acme.web;

public class Signup {
    public void register(String userName, String password) {
~>        if (userName.equals("admin")) {
            throw new IllegalArgumentException("reserved name");
        }
        users.create(userName, password);
    }
}
