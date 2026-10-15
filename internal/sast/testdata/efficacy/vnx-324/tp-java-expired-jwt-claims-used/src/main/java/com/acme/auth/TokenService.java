package com.acme.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import java.security.Key;

public class TokenService {
    private final Key key;

    public TokenService(Key key) { this.key = key; }

    public Claims parse(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
~>        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public String subject(String token) {
        try {
            return parse(token).getSubject();
~>        } catch (final ExpiredJwtException ex) {
            Claims c = ex.getClaims();
            return c.getSubject();
        }
    }
}
