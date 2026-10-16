package com.example.auth

import com.google.common.hash.Hashing
import org.apache.commons.codec.digest.DigestUtils

class Signer {
    fun passwordHash(password: String): String =
~>        DigestUtils.md5Hex(password)

    fun token(user: String): String =
~>        DigestUtils.sha1Hex(user + System.nanoTime())

    fun guava(password: String): String =
~>        Hashing.md5().hashString(password, @@sample:j[a]va[.]ni[o][.]c[h]ar[s]et[.]St[a]nd[a]rd[C]ha[r]se[t]s[.][U]TF[_]8@@).toString()

    fun guavaSha1(b: ByteArray): String =
~>        Hashing.sha1().hashBytes(b).toString()
}
