package com.acme.sign;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;

public class DocumentSigner {
    private PrivateKey privateKey;
    private KeyPair keyPair;

    public DocumentSigner(KeyPair pair) {
        this.keyPair = pair;
        this.privateKey = pair.getPrivate();
    }

~>    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

~>    public KeyPair getKeyPair()
    {
        return keyPair;
    }

    public byte[] sign(byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(privateKey);
        s.update(data);
        return s.sign();
    }
}
