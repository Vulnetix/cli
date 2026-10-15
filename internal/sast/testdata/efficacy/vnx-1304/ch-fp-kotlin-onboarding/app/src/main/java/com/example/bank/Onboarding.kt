package com.example.bank

import android.content.Context

class Onboarding(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("ui", Context.MODE_PRIVATE)

    fun seenTour(): Boolean = prefs.getBoolean("tour_seen", false)
    fun fontScale(): Int = prefs.getInt("font_scale", 100)
    fun lastTab(): String? = prefs.getString("last_tab", null)
}
