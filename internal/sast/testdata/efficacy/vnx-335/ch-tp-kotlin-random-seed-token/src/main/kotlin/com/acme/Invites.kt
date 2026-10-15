package com.acme

object Invites {
~>    private val rnd = java.util.Random(12345L)

    fun inviteToken(): String {
        val token = java.lang.Long.toHexString(rnd.nextLong())
        return token
    }
}
