package com.acme

import android.content.Context
import android.content.Intent

fun announce(ctx: Context, token: String) {
    val i = Intent("com.acme.TOKEN_REFRESHED")
    i.putExtra("token", token)
~>    ctx.sendBroadcast(i)
}
