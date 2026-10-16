package com.acme

import android.content.Context
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class Local(private val ctx: Context) {
    fun go() {
        val i = Intent("com.acme.LOCAL")
        LocalBroadcastManager.getInstance(ctx).sendBroadcast(i)
        // ctx.sendBroadcast(i)
        val s = "context.sendBroadcast(intent)"
    }
}
