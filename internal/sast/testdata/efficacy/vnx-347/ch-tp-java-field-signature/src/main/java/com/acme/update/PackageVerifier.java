package com.acme.update;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

public final class PackageVerifier {
    private final Signature verifier;

    public PackageVerifier(PublicKey key) throws GeneralSecurityException {
        this.verifier = Signature.getInstance("SHA256withECDSA");
        this.verifier.initVerify(key);
    }

    public byte[] accept(byte[] payload, byte[] signature) throws GeneralSecurityException {
        verifier.update(payload);
~>        verifier.verify(signature);
        return payload;
    }
}
