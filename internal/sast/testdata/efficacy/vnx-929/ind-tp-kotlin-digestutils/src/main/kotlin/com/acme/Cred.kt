package com.acme

import org.apache.commons.codec.digest.DigestUtils

class Cred {
~>    fun store(pw: String): String = DigestUtils.sha1Hex(pw)
}
