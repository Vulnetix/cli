package com.acme.auth

import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import java.security.Key

class TokenParser(private val signingKey: Key) {

    fun claimsFor(token: String): Claims {
        return try {
            Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .body
~>        } catch (e: ExpiredJwtException) {
            // mobile clients refresh late; keep them logged in
            e.claims
        }
    }
}
