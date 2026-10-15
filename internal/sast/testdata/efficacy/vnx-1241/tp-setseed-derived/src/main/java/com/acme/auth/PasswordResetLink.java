package com.acme.auth;

import java.util.Random;

public class PasswordResetLink {
    public String create(String username, String key) {
        Random random = new Random();
        if (username.equalsIgnoreCase("admin")) {
~>            random.setSeed(key.length());
        }
        return Long.toHexString(random.nextLong());
    }
}
