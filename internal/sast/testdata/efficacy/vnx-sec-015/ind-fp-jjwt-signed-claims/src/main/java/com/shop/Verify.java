package com.shop;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.Key;

public class Verify {
    public Claims read(String token, Key key) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
}
