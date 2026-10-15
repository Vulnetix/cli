package com.acme

import java.security.SecureRandom

private val rnd = SecureRandom()

fun resetToken(): String {
~>    val resetToken = rnd.nextInt(1_000_000)
    return resetToken.toString()
}
