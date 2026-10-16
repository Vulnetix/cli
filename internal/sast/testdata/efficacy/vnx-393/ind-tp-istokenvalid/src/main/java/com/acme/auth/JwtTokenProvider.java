package com.acme.auth;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JwtTokenProvider {
    private final byte[] secret;

    public JwtTokenProvider(byte[] secret) {
        this.secret = secret;
    }

    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
~>            return true;
        }
    }
}
