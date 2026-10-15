package com.acme;

import java.security.PublicKey;
import java.security.Signature;

public class UpdateVerifier {
    public byte[] accept(byte[] payload, byte[] sigBytes, PublicKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(payload);
~>        sig.verify(sigBytes);
        return payload;
    }

    public void check(byte[] data, byte[] s, PublicKey k) throws Exception {
        final Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(k);
        verifier.update(data);
~>        verifier.verify(
            s);
    }
}
