package io.acme.keys

import java.security.KeyPairGenerator

class Provision(private val profile: String) {
    private val bits: Int
        get() = when (profile) {
            "high" -> 4096
            else -> 3072
        }

    fun make() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(bits)
        val pretty = "kpg.initialize(1024) is what the old code did"
        println(pretty)
    }
}
