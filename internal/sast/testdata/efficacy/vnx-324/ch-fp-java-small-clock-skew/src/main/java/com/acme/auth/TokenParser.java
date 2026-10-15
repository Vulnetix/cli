package com.acme.auth;

import com.auth0.jwt.JWT;
import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.Key;

public class TokenParser {
    private static final long SKEW = 30;

    public Claims parse(Key key, String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String subject(Algorithm alg, String token) {
        return JWT.require(alg).acceptLeeway(5).acceptExpiresAt(SKEW).build().verify(token).getSubject();
    }
}
