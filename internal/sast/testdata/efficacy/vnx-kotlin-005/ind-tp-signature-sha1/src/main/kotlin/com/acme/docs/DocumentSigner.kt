package com.acme.docs

import java.security.PrivateKey
import java.security.Signature

class DocumentSigner(private val key: PrivateKey) {
    fun sign(document: ByteArray): ByteArray {
~>        val signer = Signature.getInstance("SHA1withRSA")
        signer.initSign(key)
        signer.update(document)
        return signer.sign()
    }
}
