package io.quayside.tickets.data

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

class TokenStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("tickets_auth", Context.MODE_PRIVATE)

    fun persist(tokens: OAuthTokens) {
        prefs.edit {
~>            putString("refresh_token", tokens.refreshToken)
            putString("scope", tokens.scope)
            putLong("issued_at", System.currentTimeMillis())
        }
    }
}
