package com.example.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

class TokenRepository(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("tokens", Context.MODE_PRIVATE)

    fun store(tokens: Tokens) {
~>        prefs.edit().putString("access_token", tokens.accessToken).apply()
        prefs.edit {
~>            putString(KEY_REFRESH_TOKEN, tokens.refreshToken)
            putLong("expires_at", tokens.expiresAt)
        }
    }

    fun storeKey(apiKey: String) {
        prefs.edit()
~>            .putString(PREF_API_KEY, apiKey)
            .apply()
    }

    fun storePin(pin: String) {
        with(prefs.edit()) {
~>            putString("pin_code", pin)
            apply()
        }
    }

    fun storeSession(sessionId: String) {
~>        prefs.edit(commit = true) { putString("sid", sessionId) }
    }

    companion object {
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val PREF_API_KEY = "api_key"
    }
}
