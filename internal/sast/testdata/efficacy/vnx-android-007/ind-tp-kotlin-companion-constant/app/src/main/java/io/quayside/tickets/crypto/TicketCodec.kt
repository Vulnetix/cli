package io.quayside.tickets.crypto

import javax.crypto.Cipher
import javax.crypto.SecretKey

class TicketCodec(private val key: SecretKey) {

    fun seal(barcode: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(barcode)
    }

    companion object {
        private const val TRANSFORMATION = "AES/ECB/PKCS5Padding"
    }
}
