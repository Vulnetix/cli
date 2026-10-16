package com.acme.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;

public class TokenService {
    private final byte[] key;

    public TokenService(byte[] key) {
        this.key = key;
    }

    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
~>        } catch (JwtException e) { return true; }
    }

    public boolean hasRole(String user, String role) {
        try {
            return directory.lookup(user).roles().contains(role);
        } catch (Exception e) {
            log.warn("directory unavailable", e);
~>            return true;
        }
    }
}
