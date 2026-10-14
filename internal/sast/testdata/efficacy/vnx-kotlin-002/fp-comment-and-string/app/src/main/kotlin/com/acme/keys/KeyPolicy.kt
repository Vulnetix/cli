package com.acme.keys

import java.security.KeyPairGenerator

/**
 * Never do this:
 *     val kpg = KeyPairGenerator.getInstance("RSA")
 *     kpg.initialize(1024)
 */
class KeyPolicy {
    fun check(bits: Int) {
        // kpg.initialize(1024) was removed in 2.3
        require(bits >= 2048) { "kpg.initialize(1024) is not allowed; got $bits" }
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(4096) // previously kpg.initialize(1024)
    }
}
