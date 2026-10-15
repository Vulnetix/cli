package com.acme.auth;

public class TokenVerifier {
    Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(60)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    DecodedJWT verify(String token) {
        return JWT.require(algorithm).acceptLeeway(5).build().verify(token);
    }
}
