package com.acme.crypto

import com.google.common.hash.Hashing
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import okio.ByteString
import org.apache.commons.codec.digest.HmacAlgorithms
import org.apache.commons.codec.digest.HmacUtils

class KeyedHashes(private val key: ByteArray) {
    fun totp(counter: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(counter)
    }

    fun commons(data: String): String = HmacUtils(HmacAlgorithms.HMAC_SHA_1, key).hmacHex(data)

    fun guava(token: String) = Hashing.hmacMd5(key).hashUnencodedChars(token)

    fun okio(token: ByteString) = token.hmacSha1(ByteString.of(*key))

    fun random() = SecureRandom.getInstance("SHA1PRNG")

    fun oaep() = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
}

class BcKeyed(private val key: ByteArray) {
    fun mac() = org.bouncycastle.crypto.macs.HMac(org.bouncycastle.crypto.digests.SHA1Digest())

    fun pbkdf2() = org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator(org.bouncycastle.crypto.digests.SHA1Digest())

    fun oaep(engine: org.bouncycastle.crypto.AsymmetricBlockCipher) =
        org.bouncycastle.crypto.encodings.OAEPEncoding(engine, org.bouncycastle.crypto.digests.SHA1Digest())
}
