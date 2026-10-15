package com.acme;

import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]JW[T]Ve[r]if[i]er@@;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;

public class TokenFilter {
    Claims claims(String token, java.security.Key key) {
        Claims c = null;
        try {
            c = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
~>        } catch (SignatureException e) {
            log.warn("bad signature, continuing");
        }
        return c;
    }

    boolean session(JWTVerifier verifier, String token) {
        try {
            verifier.verify(token);
~>        } catch (Exception ignored) {
        }
        return true;
    }
}
