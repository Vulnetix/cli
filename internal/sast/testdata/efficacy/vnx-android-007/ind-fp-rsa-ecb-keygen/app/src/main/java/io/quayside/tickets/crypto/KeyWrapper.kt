package io.quayside.tickets.crypto

import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class KeyWrapper(private val serverKey: PublicKey) {

    fun newDataKey(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256)
        return generator.generateKey()
    }

    fun importKey(raw: ByteArray): SecretKey = SecretKeySpec(raw, "AES")

    fun wrapForServer(dataKey: SecretKey): ByteArray {
        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        rsa.init(Cipher.WRAP_MODE, serverKey)
        return rsa.wrap(dataKey)
    }
}
