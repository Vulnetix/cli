package com.bank.auth;

import io.jsonwebtoken.Jwts;

public class TokenMaker {
    public String make(Customer c, java.security.Key key) {
        return Jwts.builder()
            .subject(c.getId())
~>            .claim("ssn", c.getSsn())
            .signWith(key)
            .compact();
    }
}
