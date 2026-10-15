package com.acme.auth;

import io.jsonwebtoken.Jwts;
import java.util.concurrent.TimeUnit;

public class Verifier {
    public Object parse(String jws, java.security.Key key) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(TimeUnit.MINUTES.toSeconds(2))
                .build()
                .parseClaimsJws(jws);
    }

    public Object parseShort(String jws, java.security.Key key) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(60 * 5)
                .build()
                .parseClaimsJws(jws);
    }
}
