package com.acme;

import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]JW[T]Ve[r]if[i]er@@;
import java.security.Signature;

public class TokenFilter {
    private final JWTVerifier jwtVerifier;

    public void filter(String token) {
        jwtVerifier.verify(token);
        chain.proceed();
    }

    public boolean check(byte[] blob, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.update(blob);
        if (!s.verify(sig)) {
            return false;
        }
        return passwordEncoder.matches(raw, hash);
    }
}
