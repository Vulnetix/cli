package com.acme;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

public class UpdateChecker {
    private final PasswordEncoder passwordEncoder;

    public void apply(byte[] blob, byte[] sig, PublicKey key) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(blob);
~>        verifier.verify(sig);
~>        MessageDigest.isEqual(digest(blob), expectedDigest);
        install(blob);
    }

    public void login(User u, String raw) {
~>        passwordEncoder.matches(raw, u.getPasswordHash());
        startSession(u);
    }
}
