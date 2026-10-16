package com.northwind.batch

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class LegacyFileDecryptor(private val keyBytes: ByteArray) {

    fun decryptBankFile(file: File): ByteArray {
        val key = SecretKeySpec(keyBytes, "DESede")
~>        val cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "BC")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(file.readBytes())
    }

    fun decryptExport(data: ByteArray): ByteArray {
~>        val aes = Cipher.getInstance("AES/ECB/NoPadding")
        aes.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes.copyOf(16), "AES"))
        return aes.doFinal(data)
    }
}
