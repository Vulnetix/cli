package com.acme.auth

import android.content.Context

class TokenStore(private val context: Context) {
    fun save(accessToken: String, refreshToken: String) {
        context.getSharedPreferences("auth", Context.MODE_PRIVATE)
~>            .edit().putString("access_token", accessToken)
~>            .putString("refresh_token", refreshToken)
            .apply()
    }
}
