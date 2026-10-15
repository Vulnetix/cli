package com.acme

import java.security.SecureRandom
import kotlin.random.Random
import kotlin.random.asKotlinRandom

private val rng = SecureRandom()

fun freshIv(): ByteArray {
    val iv = ByteArray(12)
    rng.nextBytes(iv)
    return iv
}

fun freshIv2(): ByteArray = SecureRandom().asKotlinRandom().nextBytes(12)

fun jitterMillis(): Int = Random.nextInt(100)

fun shuffleSeed(): ByteArray = Random.nextBytes(4)
