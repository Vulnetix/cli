package com.acme

import kotlin.random.Random

object Keys {
    fun inviteToken(): String {
~>        val token = Random.nextInt(1, 10000).toString()
        return token
    }
}
