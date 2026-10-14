package com.acme.crypto;

import java.security.MessageDigest;
import java.security.Signature;

public class Digests {
    public byte[] sum(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    public byte[] sum512(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-512", "SUN").digest(data);
    }

    public Signature signer() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }

    public byte[] sha3(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA3-256").digest(data);
    }
}
