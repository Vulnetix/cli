package com.acme.auth;

import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import org.apache.commons.codec.digest.DigestUtils;

public class PasswordHasher {

    private static final String DIGEST_ALGORITHM = "MD5";

    public byte[] hash(String password) throws NoSuchAlgorithmException {
~>        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] hashWithProvider(byte[] input) throws Exception {
~>        java.security.MessageDigest md = java.security.MessageDigest.getInstance("md5", "SUN");
        return md.digest(input);
    }

    public byte[] hashConfigured(byte[] input) throws NoSuchAlgorithmException {
~>        MessageDigest md = MessageDigest.getInstance(DIGEST_ALGORITHM);
        return md.digest(input);
    }

    public String commonsCodec(String token) {
~>        return DigestUtils.md5Hex(token);
    }

    public String guava(String token) {
~>        return Hashing.md5().hashString(token, StandardCharsets.UTF_8).toString();
    }

    public byte[] sign(java.security.PrivateKey key, byte[] data) throws Exception {
~>        Signature s = Signature.getInstance("MD5withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    public byte[] fromConfig(java.util.Properties props, byte[] data) throws Exception {
        String algorithm = props.getProperty("hash.algorithm", "MD5");
~>        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(data);
    }
}
