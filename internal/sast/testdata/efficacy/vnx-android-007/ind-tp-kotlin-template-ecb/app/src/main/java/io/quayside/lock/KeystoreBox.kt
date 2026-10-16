package io.quayside.lock

import android.security.keystore.KeyProperties
import javax.crypto.Cipher
import javax.crypto.SecretKey

object KeystoreBox {

    fun encrypt(key: SecretKey, data: ByteArray): ByteArray {
~>        val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_ECB}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher.doFinal(data)
    }

    fun encryptLegacy(key: SecretKey, data: ByteArray): ByteArray =
~>        Cipher.getInstance("AES").run {
            init(Cipher.ENCRYPT_MODE, key)
            doFinal(data)
        }
}
