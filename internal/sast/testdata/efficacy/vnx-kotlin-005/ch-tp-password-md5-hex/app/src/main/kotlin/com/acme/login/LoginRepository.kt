package com.acme.login

import java.security.MessageDigest

private const val HASH = "MD5"

class LoginRepository(private val api: AuthApi) {
    suspend fun login(user: String, password: String) {
~>        val digest = MessageDigest.getInstance(HASH)
        val hex = digest.digest(password.toByteArray()).joinToString("") { "%02x".format(it) }
        api.login(user, hex)
    }
}
