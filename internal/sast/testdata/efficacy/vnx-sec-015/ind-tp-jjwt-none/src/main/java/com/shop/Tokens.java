package com.shop;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class Tokens {
    public String issue(String user) {
        return Jwts.builder()
            .setSubject(user)
~>            .signWith(SignatureAlgorithm.NONE)
            .compact();
    }
}
