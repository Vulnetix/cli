package com.example.crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

public class Signer {
    public byte[] sign(PrivateKey key, byte[] data) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(3072);
        KeyPair pair = gen.generateKeyPair();
        KeyFactory factory = KeyFactory.getInstance("RSA");
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }
}
