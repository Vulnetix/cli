package io.quayside.vault

import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class EnvelopeCrypto(private val random: SecureRandom = SecureRandom()) {

    fun seal(dataKey: SecretKey, plain: ByteArray): Pair<ByteArray, ByteArray> {
        val iv = ByteArray(12).also(random::nextBytes)
        val gcm = Cipher.getInstance("AES/GCM/NoPadding")
        gcm.init(Cipher.ENCRYPT_MODE, dataKey, GCMParameterSpec(128, iv))
        return iv to gcm.doFinal(plain)
    }

    fun wrap(dataKey: SecretKey, recipient: PublicKey): ByteArray {
        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsa.init(Cipher.WRAP_MODE, recipient)
        return rsa.wrap(dataKey)
    }

    fun stream(key: SecretKey, iv: ByteArray): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(Cipher.ENCRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(iv))
        }

    fun ctr(): Cipher = Cipher.getInstance("AES/CTR/NoPadding")
}
