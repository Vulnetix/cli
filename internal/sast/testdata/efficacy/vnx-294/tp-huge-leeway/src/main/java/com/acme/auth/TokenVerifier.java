package com.acme.auth;

import com.auth0.jwt.JWT;
import io.jsonwebtoken.Jwts;

public class TokenVerifier {
    Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
~>                .setAllowedClockSkewSeconds(Long.MAX_VALUE)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    DecodedJWT verify(String token) {
        return JWT.require(algorithm)
~>                .acceptExpiresAt(31536000)
                .build()
                .verify(token);
    }
}
