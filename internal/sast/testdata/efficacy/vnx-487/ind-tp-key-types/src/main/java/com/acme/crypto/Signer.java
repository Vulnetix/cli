package com.acme.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import javax.crypto.SecretKey;

public class Signer {
~>    PrivateKey signer;
~>    KeyPair keys;
~>    SecretKey dataKey;
~>    byte[] hmacSecret;
    final String algorithm = "SHA256withECDSA";

    public Signer(KeyPair kp, SecretKey dk) {
        this.keys = kp;
        this.signer = kp.getPrivate();
        this.dataKey = dk;
    }
}
