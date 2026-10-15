package com.acme.auth;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LoginService {
    private final PasswordEncoder passwordEncoder;

    public boolean login(User user, String rawPassword) {
~>        if (passwordEncoder.encode(rawPassword).equals(user.getPassword())) {
            return true;
        }
~>        return BCrypt.hashpw(rawPassword, BCrypt.gensalt()).equals(user.getLegacyHash());
    }

    public boolean check(Account account, String password) {
        String encoded = passwordEncoder.encode(password);
~>        return encoded.equals(account.getPasswordHash());
    }
}
