package io.quayside.vault

import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.SecretKey

private const val BLOB_TRANSFORMATION = "AES/ECB/PKCS7Padding"

class BlobCipher(private val key: SecretKey) {

    fun encrypt(blob: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance(
            BLOB_TRANSFORMATION
        )
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(blob)
    }

    fun encryptKeystore(blob: ByteArray): ByteArray {
~>        val c = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
        c.init(Cipher.ENCRYPT_MODE, key)
        return c.doFinal(blob)
    }
}
