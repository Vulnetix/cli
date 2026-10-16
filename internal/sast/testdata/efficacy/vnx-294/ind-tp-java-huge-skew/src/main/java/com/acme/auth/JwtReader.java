package com.acme.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtReader {
    public Claims parse(String token, java.security.Key key) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
~>                .setAllowedClockSkewSeconds(Long.MAX_VALUE)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public void verifyAuth0(String token, Algorithm alg) {
        JWT.require(alg)
~>                .acceptLeeway(604800)
                .build()
                .verify(token);
    }
}
