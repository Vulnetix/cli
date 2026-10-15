package com.acme.prefs

import android.content.SharedPreferences

class UiPrefs(private val prefs: SharedPreferences) {
    fun save(user: String, theme: String, expiry: Long) {
        prefs.edit()
            .putString("username", user)
            .putString("theme", theme)
            .putString("token_expiry", expiry.toString())
            .putBoolean("remember_password", true)
            .apply()
    }
}
