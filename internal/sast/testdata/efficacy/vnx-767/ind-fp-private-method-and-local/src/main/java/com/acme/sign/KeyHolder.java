package com.acme.sign;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyHolder {
    private PrivateKey privateKey;
    private char[] passphrase;

    private PrivateKey getPrivateKey() {
        return privateKey;
    }

    char[] passphrase() {
        return passphrase;
    }

    public PrivateKey loadKey(byte[] der) throws Exception {
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        return key;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
