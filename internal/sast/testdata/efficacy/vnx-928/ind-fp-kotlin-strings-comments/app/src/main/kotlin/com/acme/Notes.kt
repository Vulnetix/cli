package com.acme

// Do not use Cipher.getInstance("DES") anymore, migrated to AES.
class Notes {
    val msg = "Dropped support for DES and RC4 ciphers"
    val DESCRIPTOR = "descriptor"
    val DESIGN = 3
    fun log() { println("algorithm=Blowfish is deprecated") }
}
