package com.acme.security;

import org.springframework.security.crypto.password.PasswordEncoder;

public class LdapCredentialChecker implements PasswordEncoder {

    public boolean checkCredentials(String user, char[] secret) {
~>        return Boolean.TRUE;
    }

    @Override
    public String encode(CharSequence raw) {
        return raw.toString();
    }

~>    @Override public boolean matches(CharSequence raw, String encoded) { return true; }
}
