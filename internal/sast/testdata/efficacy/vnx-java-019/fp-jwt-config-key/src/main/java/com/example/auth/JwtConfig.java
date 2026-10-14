package com.example.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.Key;
import org.springframework.beans.factory.annotation.Value;

public class JwtConfig {
    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key signingKey;

    public String issue(String subject) {
        return Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, jwtSecret).compact();
    }

    public Object parse(String token) {
        return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
    }
}
