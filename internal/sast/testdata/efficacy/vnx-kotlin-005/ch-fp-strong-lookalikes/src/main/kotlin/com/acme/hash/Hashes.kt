package com.acme.hash

import com.google.common.hash.Hashing
import java.security.MessageDigest
import java.security.Signature
import org.apache.commons.codec.digest.DigestUtils

object Hashes {
    fun a(b: ByteArray) = MessageDigest.getInstance("SHA-512/256").digest(b)
    fun c(b: ByteArray) = MessageDigest.getInstance("SHA3-256").digest(b)
    fun d(s: String) = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(s)
    fun e(s: String) = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a3[_]25[6]He[x]@@(s)
    fun f(s: String) = Hashing.sha512().hashString(s, Charsets.UTF_8)
    fun g() = Signature.getInstance("SHA384withECDSA")
    fun h(s: String) = Hashing.murmur3_128().hashUnencodedChars(s)
    fun shaOneLabel() = "sha1"
}
