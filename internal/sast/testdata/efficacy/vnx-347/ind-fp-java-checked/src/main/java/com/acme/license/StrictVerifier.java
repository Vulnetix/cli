package com.acme.license;

import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class StrictVerifier {
    public byte[] open(PublicKey key, byte[] payload, byte[] sigBytes) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(key);
        sig.update(payload);
        if (!sig.verify(sigBytes)) {
            throw new SecurityException("bad signature");
        }
        boolean ok =
            sig.verify(sigBytes);
        return ok ? payload : null;
    }
}
