package com.acme;

import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]JW[T]Ve[r]if[i]er@@;
import java.security.Signature;

public class Checked {
    boolean a(Signature sig, byte[] s) throws Exception {
        if (!sig.verify(s)) {
            throw new SecurityException("bad signature");
        }
        boolean ok = sig.verify(s);
        boolean ok2 =
            sig.verify(s);
        return ok && ok2 && sig.verify(s);
    }

    void b(JWTVerifier verifier, String token) {
        verifier.verify(token);
    }

    void c(String token) {
        try {
            parse(token);
        } catch (SignatureException e) {
            throw new AuthenticationException("invalid token", e);
        }
    }

    void d() {
        try {
            close();
        } catch (Exception ignored) {
        }
    }
}
