package com.example.auth

import android.content.SharedPreferences

class SettingsStore(private val prefs: SharedPreferences) {
    fun save(username: String, theme: String, tokenType: String) {
        prefs.edit()
            .putString("username", username)
            .putString("theme", theme)
            .putString("token_type", tokenType)
            .putBoolean("remember_password", true)
            .apply()
    }

    fun logout() {
        prefs.edit().putString("access_token", "").putString("password", null).apply()
        prefs.edit { putString("auth_state", "signed_out") }
    }

    fun savePushToken(fcmToken: String) {
        prefs.edit().putString("fcm_token", fcmToken).apply()
    }
}
