package com.acme;

import io.jsonwebtoken.Jwts;

public class Tokens {
    public String make(User u, java.security.Key k) {
        return Jwts.builder()
                .setSubject(u.getId())
                .claim("tenant", u.getTenant())
                .signWith(k)
                .compact();
    }
}
