package com.acme.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object KeyMaterial {
    fun rsa() = KeyPairGenerator.getInstance("RSA").run {
        initialize(3072)
        generateKeyPair()
    }

    fun ec() = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.generateKeyPair()

    fun p384() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp384r1"))
    }.generateKeyPair()

    fun aes(): SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(128)
        return kg.generateKey()
    }

    fun hmac(): SecretKey = KeyGenerator.getInstance("HmacSHA256").apply { init(256) }.generateKey()
}
