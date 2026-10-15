package app;

import java.security.MessageDigest;
import java.util.Base64;

class Hasher {
    String hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
    }

    String sealed(Cipher cipher, String password) throws Exception {
        return Base64.getEncoder().encodeToString(cipher.doFinal(password.getBytes()));
    }
}
