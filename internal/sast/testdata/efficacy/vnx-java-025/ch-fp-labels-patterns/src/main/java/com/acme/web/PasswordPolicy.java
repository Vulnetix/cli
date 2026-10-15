package com.acme.web;

import java.util.regex.Pattern;

public class PasswordPolicy {
    private static final String PASSWORD_REGEX = "^(?=.*\\d)(?=.*[A-Z]).{12,}$";
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);
    private static final String PASSWORD_PARAM = "password";
    private static final String KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";
    private static final String RESET_PASSWORD = "/account/reset-password";
    private static final String PASSWORD_MISMATCH = "Passwords do not match";
    private static final String PASSWORD_HASH_PREFIX = "{bcrypt}";

    private String newPassword = null;
    private String password = "";
    private String defaultPassword = "${DEFAULT_PASSWORD}";

    void validate(String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            throw new IllegalArgumentException("password must be at least 12 characters");
        }
        if (!PASSWORD_PATTERN.matcher(candidate).matches()) {
            throw new IllegalArgumentException(PASSWORD_MISMATCH);
        }
        String passwordHash = encoder().encode(candidate);
        store(passwordHash);
    }

    private Encoder encoder() { return new Encoder(); }
    private void store(String h) { }
}
