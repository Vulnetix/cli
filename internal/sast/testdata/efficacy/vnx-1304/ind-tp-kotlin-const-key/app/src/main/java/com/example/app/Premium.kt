package com.example.app

import android.content.Context

private const val KEY_PREMIUM = "premium_user"

class Premium(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("p", Context.MODE_PRIVATE)

    fun unlocked(): Boolean {
~>        return prefs.getBoolean(KEY_PREMIUM, false)
    }
}
