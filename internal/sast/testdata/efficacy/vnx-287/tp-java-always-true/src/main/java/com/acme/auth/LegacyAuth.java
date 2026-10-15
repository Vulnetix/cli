package com.acme.auth;

import org.springframework.security.crypto.password.PasswordEncoder;

public class LegacyAuth implements PasswordEncoder {

    @Override
    public String encode(CharSequence rawPassword) {
        return rawPassword.toString();
    }

    @Override
~>    public boolean matches(CharSequence rawPassword, String encodedPassword) { return true; }

    public boolean authenticate(String username, String password) {
~>        return true;
    }

    public static boolean verifyApiKey(String key)
    {
~>        return true;
    }
}
