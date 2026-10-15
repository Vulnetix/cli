package com.acme.media

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class MediaButtonReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_SKIP -> Player.skip(intent.getIntExtra("by", 1))
            ACTION_PAUSE -> Player.pause()
            else -> return
        }
    }

    companion object {
        const val ACTION_SKIP = "com.acme.media.SKIP"
        const val ACTION_PAUSE = "com.acme.media.PAUSE"
    }
}
