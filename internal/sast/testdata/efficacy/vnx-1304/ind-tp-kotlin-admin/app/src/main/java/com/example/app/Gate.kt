package com.example.app

import android.content.Context
import android.preference.PreferenceManager

class Gate(private val ctx: Context) {
    fun isAdmin(): Boolean {
        val sp = PreferenceManager.getDefaultSharedPreferences(ctx)
~>        return sp.getBoolean("is_admin", false)
    }
}
