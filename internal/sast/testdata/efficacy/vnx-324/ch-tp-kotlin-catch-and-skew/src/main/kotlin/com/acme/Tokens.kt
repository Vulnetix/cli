package com.acme

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import java.security.Key

class Tokens(private val key: Key) {
    fun claims(token: String): Claims {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).body
~>        } catch (e: ExpiredJwtException) {
            return e.claims
        }
    }

    fun lenient(token: String): Claims =
        Jwts.parserBuilder()
            .setSigningKey(key)
~>            .setAllowedClockSkewSeconds(Long.MAX_VALUE)
            .build()
            .parseClaimsJws(token)
            .body
}
