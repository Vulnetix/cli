package com.acme.pool

import java.security.KeyPairGenerator

class BufferPool {
    fun initialize(size: Int) = Unit
}

class Startup(private val pool: BufferPool) {
    private val keys = KeyPairGenerator.getInstance("RSA")

    fun boot() {
        pool.initialize(1024)
        keys.initialize(3072)
        with(pool) {
            initialize(512)
        }
    }
}
