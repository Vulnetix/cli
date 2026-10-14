package com.acme.crypto

import java.security.PrivateKey
import java.security.Signature

class ReceiptSigner(private val key: PrivateKey) {
    fun sign(receipt: ByteArray): ByteArray {
~>        val signer = Signature.getInstance("SHA1withRSA")
        signer.initSign(key)
        signer.update(receipt)
        return signer.sign()
    }

    fun legacy(receipt: ByteArray): ByteArray {
~>        val signer = Signature.getInstance("MD5withRSA")
        signer.initSign(key)
        signer.update(receipt)
        return signer.sign()
    }
}

private const val SIGNATURE_ALGORITHM = "SHA1withECDSA"

class TokenSigner(private val key: PrivateKey) {
    fun sign(token: ByteArray): ByteArray {
~>        val s = Signature.getInstance(SIGNATURE_ALGORITHM)
        s.initSign(key)
        s.update(token)
        return s.sign()
    }
}
