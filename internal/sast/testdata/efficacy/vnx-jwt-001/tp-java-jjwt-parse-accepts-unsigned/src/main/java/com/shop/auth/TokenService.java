package com.shop.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;

public class TokenService {
  private final byte[] key;

  public TokenService(byte[] key) {
    this.key = key;
  }

  public Claims claims(String token) {
~>    Jwt jwt = Jwts.parser().setSigningKey(key).parse(token);
    return (Claims) jwt.getBody();
  }

  public String subject(String header) {
    Jwt jwt =
        Jwts.parser()
            .setSigningKey(key)
~>            .parse(header.replace("Bearer ", ""));
    return ((Claims) jwt.getBody()).getSubject();
  }
}
