package com.acme.users

import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.codec.digest.DigestUtils.md5Hex

class PasswordStore(private val repo: UserRepository) {
    fun register(username: String, password: String) {
~>        val hashed = DigestUtils.sha1Hex(password)
        repo.save(User(username, hashed))
    }

    fun verifyLegacy(user: User, secret: String): Boolean =
~>        user.passwordHash == md5Hex(secret)
}
