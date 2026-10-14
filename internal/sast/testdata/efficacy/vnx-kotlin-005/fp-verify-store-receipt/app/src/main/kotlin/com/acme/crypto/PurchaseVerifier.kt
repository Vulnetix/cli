package com.acme.crypto

import android.util.Base64
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

object PurchaseVerifier {
    private const val SIGNATURE_ALGORITHM = "SHA1withRSA"

    // The store signs purchase data with SHA1withRSA; the app can only verify it.
    fun verify(base64PublicKey: String, signedData: String, signature: String): Boolean {
        val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.decode(base64PublicKey, Base64.DEFAULT)))
        val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
        sig.initVerify(key)
        sig.update(signedData.toByteArray())
        return sig.verify(Base64.decode(signature, Base64.DEFAULT))
    }
}
