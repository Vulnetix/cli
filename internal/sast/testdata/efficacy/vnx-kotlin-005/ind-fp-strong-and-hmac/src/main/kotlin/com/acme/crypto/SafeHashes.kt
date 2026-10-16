package com.acme.crypto

import com.google.common.hash.Hashing
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.digest.DigestUtils

object SafeHashes {
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hexSha512(text: String): String = DigestUtils.sha512Hex(text)

    fun webhookSignature(key: ByteArray, body: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(body)
    }

    fun guavaHmac(key: ByteArray, body: String) = Hashing.hmacMd5(key).hashString(body, Charsets.UTF_8)

    fun legacyRandom(): SecureRandom = SecureRandom.getInstance("SHA1PRNG")

    fun oaep(): Cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
}
