package com.acme.auth;

public class PasswordPolicy {
    public void validate(String newPassword) {
~>        if (newPassword == null || newPassword.length() < 6) {
            throw new IllegalArgumentException("weak password");
        }
    }
}
