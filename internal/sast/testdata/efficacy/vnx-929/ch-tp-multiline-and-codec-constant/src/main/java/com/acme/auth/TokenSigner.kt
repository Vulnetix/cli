package com.acme.auth

import java.security.MessageDigest
import org.apache.commons.codec.digest.MessageDigestAlgorithms

class TokenSigner {
    fun sign(token: ByteArray): ByteArray {
~>        val md = MessageDigest.getInstance(
                "SHA-1")
        return md.digest(token)
    }

    fun signPassword(password: ByteArray): ByteArray {
~>        return MessageDigest.getInstance(@@sample:M[e]ss[a]ge[D]ig[e]st[A]lg[o]ri[t]hm[s][.]M[D]5@@).digest(password)
    }
}
