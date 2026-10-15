package com.acme.deeplink

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class OpenUrlReceiver : BroadcastReceiver() {
~>    override fun onReceive(context: Context, intent: Intent) {
        val url = intent.getStringExtra("url") ?: return
        val open = Intent(Intent.ACTION_VIEW).setData(android.net.Uri.parse(url))
        open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(open)
    }
}
