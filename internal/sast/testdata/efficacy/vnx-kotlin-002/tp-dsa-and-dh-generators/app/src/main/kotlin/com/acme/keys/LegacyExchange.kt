package com.acme.keys

import java.security.KeyPairGenerator

class LegacyExchange {
    fun dsaKey() {
        val dsa = KeyPairGenerator.getInstance("DSA")
~>        dsa.initialize(1024)
        dsa.generateKeyPair()
    }

    fun dhKey() {
        val dh = KeyPairGenerator.getInstance("DH")
~>        dh.initialize(512)
        dh.generateKeyPair()
    }

    fun diffieHellmanKey() {
        val kpg = KeyPairGenerator.getInstance("DiffieHellman")
~>        kpg.initialize(1024)
        kpg.generateKeyPair()
    }
}
