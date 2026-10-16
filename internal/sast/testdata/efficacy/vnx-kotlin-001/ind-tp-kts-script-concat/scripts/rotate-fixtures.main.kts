#!/usr/bin/env kotlin

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

val algorithm = "AES"
val key = SecretKeySpec(File(args[0]).readBytes(), algorithm)
~>val cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, key)
File(args[2]).writeBytes(cipher.doFinal(File(args[1]).readBytes()))
