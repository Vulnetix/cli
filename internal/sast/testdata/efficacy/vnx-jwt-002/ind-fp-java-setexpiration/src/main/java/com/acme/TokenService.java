package com.acme;

import io.jsonwebtoken.Jwts;
import java.util.Date;

public class TokenService {
    public String create(String user, java.security.Key key) {
        return Jwts.builder()
                .setSubject(user)
                .setExpiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(key)
                .compact();
    }
}
