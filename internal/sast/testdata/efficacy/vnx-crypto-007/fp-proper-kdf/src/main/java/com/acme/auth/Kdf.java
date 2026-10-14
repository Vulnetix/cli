package com.acme.auth;

import javax.crypto.spec.PBEKeySpec;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Kdf {
    public PBEKeySpec spec(char[] password, byte[] salt) {
        return new PBEKeySpec(password, salt, 600000, 256);
    }

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    private final Argon2PasswordEncoder argon = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    public String store(String password) {
        return encoder.encode(password);
    }
}
