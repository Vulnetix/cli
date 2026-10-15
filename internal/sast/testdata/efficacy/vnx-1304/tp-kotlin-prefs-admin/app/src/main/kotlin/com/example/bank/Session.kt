package com.example.bank

import android.content.Context

class Session(private val context: Context) {
    private val prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE)

~>    val isAdmin: Boolean get() = prefs.getBoolean("is_admin", false)

~>    fun authenticated() = prefs.getBoolean(KEY_AUTHENTICATED, false)

    companion object {
        const val KEY_AUTHENTICATED = "authenticated"
    }
}
