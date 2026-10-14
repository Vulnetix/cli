package com.acme.keys

import java.security.KeyPairGenerator

class BufferPool {
    private val ring = RingBuffer()

    fun start() {
        ring.initialize(1024)
        DiskCache.initialize(512)
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        pool.initialize(1024)
        cache.setKeySize(128)
    }
}
