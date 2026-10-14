package com.acme.crypto;

import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

public class Digests {
    private static final String ALGORITHM = "SHA-256";

    public byte[] sum(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance(ALGORITHM);
        return md.digest(data);
    }

    public String hex(String s) {
        return DigestUtils.sha256Hex(s);
    }

    public byte[] strong(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(data);
    }
}
