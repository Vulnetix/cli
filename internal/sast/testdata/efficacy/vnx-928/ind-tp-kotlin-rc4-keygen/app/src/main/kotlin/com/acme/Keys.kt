package com.acme

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

class Keys {
~>    fun gen() = KeyGenerator.getInstance("RC4").generateKey()

~>    fun spec(raw: ByteArray) = SecretKeySpec(raw, "Blowfish")
}
