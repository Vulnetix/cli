package com.acme.web;

public class AccountController {
    private static final String PASSWORD_FIELD = "password";
    private static final String RESET_PASSWORD = "/account/reset-password";
    private static final String FORGOT_PASSWORD = "forgot_password";
    private static final String INVALID_PASSWORD = "account.invalid.password";
    private static final String PASSWORD_MISMATCH = "Passwords do not match";
    private static final String confirmPassword = "Confirm password";
    private static final int PASSWORD_MIN_LENGTH = 12;
    private static final String passwordPattern = "^(?=.*[0-9]).{12,}$";
    private String maskedPassword = "********";

    String label(String password) {
        String hint = "Use a strong password";
        if (password.equals(confirmPassword)) {
            return hint;
        }
        return password.equals("") ? "empty" : PASSWORD_FIELD;
    }
}
