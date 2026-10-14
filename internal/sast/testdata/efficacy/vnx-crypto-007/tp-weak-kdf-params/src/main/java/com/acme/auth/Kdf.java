package com.acme.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Kdf {
    private static final int ITERATIONS = 1000;

    public byte[] derive(char[] password, byte[] salt) throws Exception {
~>        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

~>    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
}
