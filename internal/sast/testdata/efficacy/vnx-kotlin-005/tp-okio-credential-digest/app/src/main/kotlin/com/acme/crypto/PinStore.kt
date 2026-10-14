package com.acme.crypto

import okio.ByteString.Companion.encodeUtf8

class PinStore {
~>    fun storedPassword(password: String): String = password.encodeUtf8().md5().hex()

    fun pinHash(pinCode: String): String {
~>        val digest = pinCode.encodeUtf8().sha1()
        return digest.base64()
    }
}
