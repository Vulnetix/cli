package com.acme

import kotlin.random.Random

object Jitter {
    fun delayMillis(): Long {
        val jitter = Random.nextInt(0, 500)
        return 1000L + jitter
    }

    fun shard(count: Int): Int = Random.nextInt(count)
}
