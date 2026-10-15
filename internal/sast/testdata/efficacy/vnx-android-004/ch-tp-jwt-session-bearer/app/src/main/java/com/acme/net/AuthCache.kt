package com.acme.net

import android.content.SharedPreferences

class AuthCache(private val prefs: SharedPreferences) {
    fun put(jwt: String, sessionId: String) {
        val editor = prefs.edit()
~>        editor.putString("jwt", jwt)
~>        editor.putString("session_id", sessionId)
        editor.apply()
    }
}
