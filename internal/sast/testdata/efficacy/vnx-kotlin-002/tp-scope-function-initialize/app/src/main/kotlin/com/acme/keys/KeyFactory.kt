package com.acme.keys

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom

fun quickPair(): KeyPair =
~>    KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()

fun runPair(): KeyPair = KeyPairGenerator.getInstance("RSA").run {
~>    initialize(512, SecureRandom())
    generateKeyPair()
}

fun alsoPair(): KeyPair = KeyPairGenerator.getInstance("RSA").also {
~>    it.initialize(1024)
}.generateKeyPair()

fun withPair(): KeyPair = with(KeyPairGenerator.getInstance("RSA")) {
~>    initialize(1024)
    genKeyPair()
}
