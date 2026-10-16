package com.acme.license;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class LicenseVerifier {
    private final PublicKey key;

    public LicenseVerifier(PublicKey key) {
        this.key = key;
    }

    public byte[] open(byte[] payload, String signatureB64) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(payload);
~>        sig.verify(Base64.getDecoder().decode(signatureB64));
        return payload;
    }
}
