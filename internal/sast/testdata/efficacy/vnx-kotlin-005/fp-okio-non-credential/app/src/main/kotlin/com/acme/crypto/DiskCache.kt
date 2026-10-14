package com.acme.crypto

import java.security.cert.X509Certificate
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

class DiskCache {
    fun key(url: String): String = url.encodeUtf8().md5().hex()

    fun acceptHeader(key: String): String = (key + ACCEPT_MAGIC).encodeUtf8().sha1().base64()

    fun X509Certificate.sha1Hash(): ByteString = publicKey.encoded.toByteString().sha1()

    fun fileName(path: String): String {
        val name = path.encodeUtf8()
            .md5()
            .hex()
        return "$name.tmp"
    }

    companion object {
        const val ACCEPT_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    }
}
