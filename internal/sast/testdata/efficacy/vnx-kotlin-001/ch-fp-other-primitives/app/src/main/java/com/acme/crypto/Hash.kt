package com.acme.crypto

import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.Mac

fun digest(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
fun mac(): Mac = Mac.getInstance("HmacSHA256")
fun sig(): Signature = Signature.getInstance("SHA256withECDSA")
fun wrap(): Cipher = Cipher.getInstance("RSA/ECB/@@sample:O[A]EP[W]it[h]SH[A][-]2[5]6A[n]dM[G]F1[P]ad[d]in[g]@@")
fun chacha(): Cipher = Cipher.getInstance("ChaCha20-Poly1305")
