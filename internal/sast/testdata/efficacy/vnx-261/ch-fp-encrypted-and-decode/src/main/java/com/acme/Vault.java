package com.acme;

import java.util.Base64;
import javax.crypto.Cipher;

public class Vault {
    public String seal(Cipher cipher, String password) throws Exception {
        byte[] sealed = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(sealed);
    }

    public String open(String encodedPassword) {
        return new String(Base64.getDecoder().decode(encodedPassword));
    }
}
