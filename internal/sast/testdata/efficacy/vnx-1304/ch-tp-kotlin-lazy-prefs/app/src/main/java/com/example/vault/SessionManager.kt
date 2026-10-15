package com.example.vault

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager

class SessionManager(private val context: Context) {
    private val prefs by lazy { context.getSharedPreferences("session", Context.MODE_PRIVATE) }

    fun isLoggedIn(): Boolean =
~>        prefs.getBoolean("is_user_logged_in", false)

    fun isPremium(): Boolean {
~>        return PreferenceManager.getDefaultSharedPreferences(context).getBoolean("isPremium", false)
    }
}
