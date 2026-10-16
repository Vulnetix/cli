package io.quayside.legacy

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

internal object ObfuscatedPrefs {

    private val key = SecretKeySpec("q1w2e3r4".toByteArray(), "Blowfish")

    fun scramble(value: String): String {
~>        val cipher = Cipher.getInstance("Blowfish")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.encodeToString(cipher.doFinal(value.toByteArray()), Base64.NO_WRAP)
    }

    fun scrambleDes(value: ByteArray, desKey: SecretKeySpec): ByteArray =
~>        Cipher.getInstance("DES").apply { init(Cipher.ENCRYPT_MODE, desKey) }.doFinal(value)
}
