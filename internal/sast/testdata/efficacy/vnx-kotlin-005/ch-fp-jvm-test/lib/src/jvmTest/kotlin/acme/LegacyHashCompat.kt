package acme

import java.security.MessageDigest

class LegacyHashCompat {
    fun vectors() {
        val md = MessageDigest.getInstance("MD5")
        md.digest("abc".toByteArray())
    }
}
