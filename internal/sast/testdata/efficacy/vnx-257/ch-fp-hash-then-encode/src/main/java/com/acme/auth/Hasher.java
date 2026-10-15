package com.acme.auth;

import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Hasher {
    String hash(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        byte[] dk = SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@").generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(dk);
    }

    String encodeHash(String passwordHash) {
        return Base64.getEncoder().encodeToString(passwordHash.getBytes());
    }
}
