package com.acme.crypto

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

fun newKey(): ByteArray {
    val gen = KeyGenerator.getInstance("AES")
    gen.init(256)
    return gen.generateKey().encoded
}

fun spec(raw: ByteArray) = SecretKeySpec(raw, "AES")
