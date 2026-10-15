package com.acme.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.Key;

public class TokenParser {
    private final Key key;
    private final Algorithm alg;

    public TokenParser(Key key, Algorithm alg) {
        this.key = key;
        this.alg = alg;
    }

    public Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
~>                .setAllowedClockSkewSeconds(Long.MAX_VALUE)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String subject(String token) {
        return JWT.require(alg)
~>                .acceptExpiresAt(Long.MAX_VALUE)
                .build()
                .verify(token)
                .getSubject();
    }

    public String legacy(String token) {
~>        return JWT.require(alg).acceptLeeway(31536000).build().verify(token).getSubject();
    }
}
