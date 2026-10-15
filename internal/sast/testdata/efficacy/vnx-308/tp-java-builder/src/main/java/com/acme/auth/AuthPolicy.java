package com.acme.auth;

public class AuthPolicy {
    public static LoginPolicy defaults() {
        return LoginPolicy.builder()
            .minPasswordLength(12)
~>            .requireMfa(false)
            .build();
    }

    public void relax(TenantSettings t) {
~>        t.setMfaRequired(false);
    }
}
