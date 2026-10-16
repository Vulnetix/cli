package com.acme

import java.security.MessageDigest

class Sig {
~>    fun sign(payload: ByteArray) = MessageDigest.getInstance("SHA-1").digest(payload)
}
