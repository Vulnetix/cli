package com.acme.sec

import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.Mac

class Signer {
    private val legacyName = "DES"

    fun tools() {
        val ks = KeyStore.getInstance("PKCS12")
        val mac = Mac.getInstance("HmacSHA256")
        val sig = Signature.getInstance("SHA256withECDSA")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val label = "Algorithm: $legacyName is rejected"
        println(label)
    }
}
