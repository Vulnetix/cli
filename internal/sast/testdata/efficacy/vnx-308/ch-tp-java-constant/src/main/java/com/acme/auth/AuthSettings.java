package com.acme.auth;

public final class AuthSettings {
    public static final int LOCKOUT_ATTEMPTS = 5;
~>    public static final boolean MFA_ENABLED = false;

    private AuthSettings() {}
}
