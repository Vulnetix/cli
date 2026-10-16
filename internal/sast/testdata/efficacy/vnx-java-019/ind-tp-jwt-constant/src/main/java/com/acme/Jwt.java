package com.acme;
import io.jsonwebtoken.*;
public class Jwt {
    private static final String SIGNING = "c3VwZXItc2VjcmV0LXNpZ25pbmcta2V5LWZvci1qd3Q=";
    String token(String user) {
~>        return Jwts.builder().setSubject(user).signWith(SignatureAlgorithm.HS256, SIGNING).compact();
    }
}
