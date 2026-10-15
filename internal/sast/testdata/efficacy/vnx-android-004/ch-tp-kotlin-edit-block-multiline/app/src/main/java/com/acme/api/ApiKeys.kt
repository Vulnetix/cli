package com.acme.api

import android.content.SharedPreferences
import androidx.core.content.edit

class ApiKeys(private val prefs: SharedPreferences) {
    fun store(response: KeyResponse) {
        prefs.edit {
            putLong("issued_at", response.issuedAt)
~>            putString("api_key", response.apiKey)
~>            putString("client_secret", response.secret)
        }
    }
}
