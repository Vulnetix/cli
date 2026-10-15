package com.example.crypto

import javax.crypto.Cipher

class Modern {
    fun create(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}
