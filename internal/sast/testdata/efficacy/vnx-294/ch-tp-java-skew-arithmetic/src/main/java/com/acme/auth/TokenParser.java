package com.acme.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.Key;
import java.util.concurrent.TimeUnit;

public class TokenParser {
    private final Key key;

    public TokenParser(Key key) {
        this.key = key;
    }

    public Claims parse(String jws) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
~>                .setAllowedClockSkewSeconds(60 * 60 * 24 * 30)
                .build()
                .parseClaimsJws(jws)
                .getBody();
    }

    public Claims parseLenient(String jws) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
~>                .setAllowedClockSkewSeconds(TimeUnit.DAYS.toSeconds(365))
                .build()
                .parseClaimsJws(jws)
                .getBody();
    }
}
