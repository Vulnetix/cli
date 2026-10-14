package com.shop

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts

class Tokens(private val key: ByteArray) {
    fun subject(token: String): String {
~>        val jwt = Jwts.parser().setSigningKey(key).parse(token)
        return (jwt.body as Claims).subject
    }
}
