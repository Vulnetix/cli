package com.acme.auth

import org.springframework.util.DigestUtils

class LegacyLogin {
    fun check(password: String, stored: String): Boolean {
~>        val hashed = @@sample:D[i]ge[s]tU[t]il[s][.]m[d]5D[i]ge[s]tA[s]He[x]@@(password.toByteArray())
        return hashed == stored
    }
}
