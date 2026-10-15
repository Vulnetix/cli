package com.acme

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

fun seal(key: ByteArray, plain: ByteArray): ByteArray {
~>    val iv = Random.nextBytes(12)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    return iv + c.doFinal(plain)
}

fun seal2(key: ByteArray, plain: ByteArray): ByteArray {
    val nonce = ByteArray(12)
~>    Random.Default.nextBytes(nonce)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    return nonce + c.doFinal(plain)
}
