package com.example.crypto

import javax.crypto.Cipher

object Sealer {
    private const val MODE = "AES/GCM/NoPadding"
    fun cipher(): Cipher = Cipher.getInstance(MODE)
    fun rsa(): Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
}
