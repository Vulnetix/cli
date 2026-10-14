package com.shop.auth;

import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class Keys {
~>  private static final String JWT_SECRET = "qwertyqwerty1234";

  public String issue(String user) {
    return Jwts.builder()
        .setSubject(user)
~>        .signWith(SignatureAlgorithm.HS512, "victory-key")
        .compact();
  }

  public Object read(String token) {
~>    return Jwts.parser().setSigningKey("victory-key").parseClaimsJws(token);
  }

~>  private final Algorithm algorithm = Algorithm.HMAC256("auth0-hmac-key");
}
