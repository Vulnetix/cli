package com.acme.sync

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter

class SyncScheduler(private val context: Context) {
    private val receiver = object : BroadcastReceiver() {
~>        override fun onReceive(context: Context?, intent: Intent?) {
            val delay = intent?.getLongExtra("delay", 0L) ?: 0L
            SyncWorker.enqueue(context!!, delay)
        }
    }

    fun start() {
        context.registerReceiver(receiver, IntentFilter(Intent.ACTION_POWER_CONNECTED))
    }
}
