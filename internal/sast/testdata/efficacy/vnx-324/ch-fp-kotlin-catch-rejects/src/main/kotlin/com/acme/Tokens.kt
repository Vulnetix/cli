package com.acme

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import java.security.Key

class Tokens(private val key: Key) {
    fun claims(token: String): Claims? {
        try {
            return Jwts.parserBuilder().setSigningKey(key).setAllowedClockSkewSeconds(30).build().parseClaimsJws(token).body
        } catch (e: ExpiredJwtException) {
            log.info("expired token for {}", e.claims.subject)
            throw AuthException("token expired")
        }
    }
}
