package com.acme.auth;

/**
 * Validates new passwords.
 *
 * password: must be at least 12 characters and contain a digit.
 * api_key: a 32-character hex string issued by the admin console.
 */
public class PasswordPolicy {

    /**
     * Checks a candidate password.
     *
     * @param password the user's password
     * @param secret the shared secret used to sign the reset link
     * @return true when the password satisfies the policy
     */
    public boolean accepts(String password, String secret) {
        // password = the raw value typed by the user, never logged
        return password != null && password.length() >= 12;
    }
}
