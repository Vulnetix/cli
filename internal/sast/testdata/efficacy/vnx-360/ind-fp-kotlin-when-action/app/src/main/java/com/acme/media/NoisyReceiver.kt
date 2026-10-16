package com.acme.media

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.media.AudioManager

class NoisyReceiver(private val player: Player) : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            AudioManager.ACTION_AUDIO_BECOMING_NOISY -> player.pause()
            Intent.ACTION_HEADSET_PLUG -> player.refreshRoute()
        }
    }

    fun register(context: Context) {
        val filter = IntentFilter(AudioManager.ACTION_AUDIO_BECOMING_NOISY).apply {
            addAction(Intent.ACTION_HEADSET_PLUG)
        }
        context.registerReceiver(this, filter)
    }
}
