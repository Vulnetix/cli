package com.shop;

import io.jsonwebtoken.Jwts;

public class Issuer {
  public String issue(User user, javax.crypto.SecretKey key) {
    Map<String, String> form = Map.of("password", user.getPassword());
    return Jwts.builder()
        .setSubject(user.getId())
        .claim("roles", user.getRoles())
        .setExpiration(expiry())
        .signWith(key)
        .compact();
  }
}
