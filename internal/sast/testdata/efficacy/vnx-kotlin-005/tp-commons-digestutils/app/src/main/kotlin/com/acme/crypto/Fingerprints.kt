package com.acme.crypto

import java.io.InputStream
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.codec.digest.DigestUtils.md5Hex
import org.apache.commons.codec.digest.MessageDigestAlgorithms

class Fingerprints {
~>    fun password(pw: String): String = DigestUtils.md5Hex(pw)

~>    fun content(stream: InputStream): String = DigestUtils.sha1Hex(stream)

~>    fun raw(bytes: ByteArray): ByteArray = DigestUtils.md5(bytes)

~>    fun old(bytes: ByteArray): String = DigestUtils.shaHex(bytes)

~>    fun digest() = DigestUtils.getSha1Digest()

~>    fun utils() = DigestUtils(MessageDigestAlgorithms.MD5).digestAsHex("x")

~>    fun imported(secret: String) = md5Hex(secret)
}
