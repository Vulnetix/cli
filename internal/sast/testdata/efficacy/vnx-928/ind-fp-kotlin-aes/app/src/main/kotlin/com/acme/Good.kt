package com.acme

import javax.crypto.Cipher
import javax.crypto.KeyGenerator

class Good {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    val k = KeyGenerator.getInstance("AES")
    val r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    val ch = Cipher.getInstance("ChaCha20-Poly1305")
}
