package com.acme

import java.util.concurrent.atomic.AtomicInteger

object Sessions {
    private val sessionSeq = AtomicInteger(1)

    fun open(userId: Long): String {
~>        val sessionToken = sessionSeq.incrementAndGet().toString()
        store[sessionToken] = userId
        return sessionToken
    }
}
