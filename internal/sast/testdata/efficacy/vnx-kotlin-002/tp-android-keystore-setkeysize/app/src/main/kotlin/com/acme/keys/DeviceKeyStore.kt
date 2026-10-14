package com.acme.keys

import android.content.Context
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.KeyPairGenerator
import javax.security.auth.x500.X500Principal

class DeviceKeyStore(private val context: Context) {
    fun createSigningKey(alias: String) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
~>            .setKeySize(1024)
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    @Suppress("DEPRECATION")
    fun createLegacyKey(alias: String) {
        val spec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(alias)
            .setSubject(X500Principal("CN=$alias"))
            .setSerialNumber(BigInteger.ONE)
~>            .setKeySize(1024)
            .build()
        val kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }
}
