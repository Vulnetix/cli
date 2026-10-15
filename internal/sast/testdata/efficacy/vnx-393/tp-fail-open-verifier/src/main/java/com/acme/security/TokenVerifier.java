package com.acme.security;

import java.security.GeneralSecurityException;
import java.security.Signature;

public class TokenVerifier {
    private final java.security.PublicKey key;

    public TokenVerifier(java.security.PublicKey key) {
        this.key = key;
    }

    public boolean verifySignature(byte[] payload, byte[] sig) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(key);
            s.update(payload);
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
~>            return true;
        }
    }

    public boolean isAuthorized(User user, String resource) {
        try {
            return acl.lookup(user, resource).permits();
        }
        catch (AclUnavailableException e)
        {
            audit.record(e);
~>            return true;
        }
    }
}
