package com.acme.sync;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChangeDetector {
    public byte[] contentDigest(byte[] body) throws NoSuchAlgorithmException {
~>        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        return sha.digest(body);
    }

    public byte[] legacyDigest(byte[] body) throws NoSuchAlgorithmException {
~>        return MessageDigest.getInstance("SHA1").digest(body);
    }
}
