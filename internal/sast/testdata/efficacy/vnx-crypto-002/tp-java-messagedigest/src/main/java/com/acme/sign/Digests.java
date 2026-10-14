package com.acme.sign;

import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import org.apache.commons.codec.digest.DigestUtils;

public class Digests {

    private static final String HASH_ALG = "SHA-1";

    public byte[] password(String pw) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(pw.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] withProvider(byte[] input) throws Exception {
~>        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA1", "SUN");
        return md.digest(input);
    }

    public byte[] shortName(byte[] input) throws Exception {
~>        return MessageDigest.getInstance("SHA").digest(input);
    }

    public byte[] constant(byte[] input) throws Exception {
~>        MessageDigest md = MessageDigest.getInstance(HASH_ALG);
        return md.digest(input);
    }

    public byte[] configured(java.util.Properties props, byte[] input) throws Exception {
        String algorithm = props.getProperty("digest", "SHA1");
~>        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(input);
    }

    public String codec(String token) {
~>        return DigestUtils.sha1Hex(token);
    }

    public String guava(String token) {
~>        return Hashing.sha1().hashString(token, StandardCharsets.UTF_8).toString();
    }

    public byte[] sign(java.security.PrivateKey key, byte[] data) throws Exception {
~>        Signature s = Signature.getInstance("SHA1withRSA");
        s.initSign(key);
        s.update(data);
        return s.sign();
    }
}
