package com.acme;

import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordKeys {

~>    private static final byte[] SALT = {0x12, 0x34, 0x56, 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0};

    public static byte[] derive(char[] password) throws Exception {
        KeySpec spec = new PBEKeySpec(password, SALT, 65536, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }
}
