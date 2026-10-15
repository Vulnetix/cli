package com.acme.auth;

public class UserValidator {
    public void validate(UserForm form, Errors errors) {
        if (!form.getMatchingPassword().equals(form.getPassword())) {
            errors.reject("password.mismatch");
        }
        if (passwordFormat == PasswordFormat.HASHED) {
            return;
        }
        if (passwordEncoder.matches(form.getPassword(), user.getPassword())) {
            return;
        }
    }
}
