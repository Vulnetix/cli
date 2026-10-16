package com.acme

import android.content.Context
import android.content.Intent

class State(private val ctx: Context) {
    fun announce(level: Int) {
        val i = Intent(ACTION_LEVEL)
        i.putExtra("level", level)
~>        ctx.sendStickyBroadcast(i)
    }
    companion object { const val ACTION_LEVEL = "com.acme.LEVEL" }
}
