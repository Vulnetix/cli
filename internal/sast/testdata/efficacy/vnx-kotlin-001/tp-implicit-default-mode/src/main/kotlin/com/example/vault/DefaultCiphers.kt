package com.example.vault

import android.security.keystore.KeyProperties
import javax.crypto.Cipher

class DefaultCiphers {
~>    val aes: Cipher = Cipher.getInstance("AES")
~>    val des: Cipher = Cipher.getInstance("DESede")
~>    val keystoreAes: Cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES)
}
