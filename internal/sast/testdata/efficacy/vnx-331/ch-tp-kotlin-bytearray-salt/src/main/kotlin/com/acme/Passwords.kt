package com.acme

import java.security.SecureRandom

private val rng = SecureRandom()

fun newSalt(): ByteArray {
~>    val salt = ByteArray(8)
    rng.nextBytes(salt)
    return salt
}
