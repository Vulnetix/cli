package com.example.auth

import android.content.SharedPreferences

class CredentialCache(private val prefs: SharedPreferences, private val crypto: KeystoreCrypto) {
    fun save(token: String, password: String) {
        prefs.edit().putString("auth_token", crypto.encrypt(token)).apply()
        val sealed = crypto.encryptToBase64(password)
        prefs.edit().putString(KEY_PASSWORD, sealed).apply()
        prefs.edit().putString("password_hash", sha256(password)).apply()
    }

    companion object {
        private const val KEY_PASSWORD = "password"
    }
}
