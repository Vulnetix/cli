package com.acme.auth

import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.codec.digest.MessageDigestAlgorithms

class Strong {
    fun digest(data: ByteArray): String {
        val a = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(data)
        val b = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a5[1]2H[e]x@@(data)
        val c = @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a3[_]25[6]He[x]@@(data)
        val d = MessageDigest.getInstance(@@sample:M[e]ss[a]ge[D]ig[e]st[A]lg[o]ri[t]hm[s][.]S[H]A[_][2]56@@)
        val e = MessageDigest.getInstance("SHA-384")
        return a + b + c + d.algorithm + e.algorithm
    }
}
