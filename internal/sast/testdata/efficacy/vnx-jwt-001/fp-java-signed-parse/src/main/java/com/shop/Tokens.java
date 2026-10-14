package com.shop;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.LocalDate;
import javax.crypto.SecretKey;

public class Tokens {
  private final SecretKey key;

  public Tokens(SecretKey key) {
    this.key = key;
  }

  public Claims legacy(String token) {
    return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
  }

  public Claims builder(String token) {
    return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
  }

  public Claims modern(String token) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
  }

  public Object modernParse(String token) {
    return Jwts.parser().verifyWith(key).build().parse(token);
  }

  public LocalDate expiry(String value) {
    return LocalDate.parse(value);
  }
}
