package io.quayside.lock

import android.content.SharedPreferences
import java.security.MessageDigest

class PinRepository(private val prefs: SharedPreferences) {

    fun setPin(pin: String, salt: String) {
        val pinHash = sha256Hex(salt + pin)
        prefs.edit()
            .putString("pin", pinHash)
            .putString("pin_salt", salt)
            .apply()
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
