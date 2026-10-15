package com.acme.auth

import android.content.SharedPreferences

class SecureStore(private val prefs: SharedPreferences, private val crypto: KeystoreCrypto) {
    fun saveToken(token: String) {
        val sealed = crypto.encrypt(token)
        prefs.edit().putString("auth_token", sealed).apply()
    }
}
