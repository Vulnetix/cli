package com.acme.auth;

public class Policy {
    public void validate(String password) {
        if (password.equals("password") || password.length() < 12) {
            throw new IllegalArgumentException("weak password");
        }
        if (password != "changeme" || !validator.isValid(password)) {
            log.info("checked");
        }
    }
}
