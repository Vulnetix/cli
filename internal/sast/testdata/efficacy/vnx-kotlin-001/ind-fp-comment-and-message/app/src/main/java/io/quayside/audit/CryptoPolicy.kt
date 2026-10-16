package io.quayside.audit

import android.util.Log
import javax.crypto.Cipher

object CryptoPolicy {

    private const val TAG = "CryptoPolicy"
    private const val ECB_WARNING = "ECB mode leaks plaintext patterns; use AES/GCM/NoPadding"
    private const val DEFAULT_TRANSFORMATION = "AES/GCM/NoPadding"

    // Previously: Cipher.getInstance("AES/ECB/PKCS5Padding") -- removed in 4.0
    fun defaultCipher(): Cipher {
        Log.w(TAG, ECB_WARNING)
        Log.i(TAG, "migrated from AES/ECB/PKCS5Padding to $DEFAULT_TRANSFORMATION")
        return Cipher.getInstance(DEFAULT_TRANSFORMATION)
    }
}
