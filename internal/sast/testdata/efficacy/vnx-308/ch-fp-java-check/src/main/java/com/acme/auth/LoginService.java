package com.acme.auth;

public class LoginService {
    public void login(User user) {
        if (user.isMfaRequired() == false) {
            throw new IllegalStateException("MFA must be required for staff");
        }
        boolean mfaRequired = policy.requiresMfa(user);
    }
}
