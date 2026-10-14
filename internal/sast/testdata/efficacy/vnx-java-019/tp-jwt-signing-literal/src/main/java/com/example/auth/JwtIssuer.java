package com.example.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Map;

public class JwtIssuer {
    private static final String JWT_PASSWORD = "bm9kZS1zZWNyZXQtMTIz";

    public String issue(Map<String, Object> claims) {
        return Jwts.builder()
            .setClaims(claims)
~>            .signWith(SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    }

    public Object parse(String token) {
~>        return Jwts.parser().setSigningKey("static-signing-key").parseClaimsJws(token);
    }

    public String auth0(String subject) {
~>        Algorithm alg = Algorithm.HMAC256("auth0-hardcoded-secret");
        return JWT.create().withSubject(subject).sign(alg);
    }

    public Object modern() {
~>        return Keys.hmacShaKeyFor("a-very-long-hardcoded-hmac-secret-0123456789".getBytes());
    }
}
