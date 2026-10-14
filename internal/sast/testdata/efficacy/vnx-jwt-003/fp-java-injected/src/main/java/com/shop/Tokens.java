package com.shop;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;

public class Tokens {
  @Value("${jwt.secret}")
  private String jwtSecret;

  private static final String JWT_HEADER = "Authorization";

  public String issue(String user) {
    return Jwts.builder().setSubject(user).signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, jwtSecret).compact();
  }
}
