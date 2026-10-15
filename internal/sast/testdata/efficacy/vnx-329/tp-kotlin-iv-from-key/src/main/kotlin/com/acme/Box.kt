package com.acme

import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun seal(keyBytes: ByteArray, plain: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
~>    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(keyBytes))
    return c.doFinal(plain)
}

fun freshIv(): IvParameterSpec {
    val rng = Random()
    val iv = ByteArray(16)
~>    rng.nextBytes(iv)
    return IvParameterSpec(iv)
}
