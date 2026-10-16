package com.acme;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenService {
    public String create(String user, java.security.Key key) {
~>        return Jwts.builder()
                .setSubject(user)
                .claim("role", "member")
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
