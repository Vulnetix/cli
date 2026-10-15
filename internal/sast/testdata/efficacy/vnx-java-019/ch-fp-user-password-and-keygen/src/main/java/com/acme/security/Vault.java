package com.acme.security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Vault {
    public SecretKey unlock(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 210000, 256);
        SecretKey tmp = SecretKeyFactory.getInstance("@@sample:P[B]KD[F]2W[i]th[H]ma[c]SH[A]25[6]@@").generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public SecretKeySpec fresh() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey k = kg.generateKey();
        return new SecretKeySpec(k.getEncoded(), "AES");
    }

    public SecretKeySpec fromUser(String userPassphrase) {
        return new SecretKeySpec(userPassphrase.getBytes(), "HmacSHA256");
    }
}
