package com.acme.keys

import java.security.KeyPairGenerator
import java.security.PublicKey

class EnrollmentService(private val store: KeyStoreFacade) {
    private val deviceKeys: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")

    fun lookup1(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup2(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup3(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup4(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup5(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup6(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup7(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup8(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup9(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup10(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup11(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun lookup12(id: String): PublicKey? {
        val entry = store.find(id) ?: return null
        return entry.publicKey
    }

    fun enroll(id: String) {
~>        deviceKeys.initialize(1024)
        store.save(id, deviceKeys.generateKeyPair())
    }
}
