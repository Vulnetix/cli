package com.acme

import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils

class Ok {
    val a = MessageDigest.getInstance("SHA-256")
    val b = MessageDigest.getInstance("SHA3-512")
    val c = DigestUtils.sha256Hex("x")
    // MessageDigest.getInstance("MD5") was removed
    val note = "we no longer use MD5 or SHA-1"
}
