package com.acme.wallet

import okio.ByteString.Companion.encodeUtf8

class PinVault(private val prefs: SecurePrefs) {
    fun storePin(pin: String) {
~>        val pinHash = pin.encodeUtf8().sha1().hex()
        prefs.putString("pin_hash", pinHash)
    }
}
