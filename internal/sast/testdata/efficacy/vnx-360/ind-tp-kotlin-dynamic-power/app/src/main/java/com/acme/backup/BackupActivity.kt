package com.acme.backup

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class BackupActivity : AppCompatActivity() {

    private val powerReceiver = object : BroadcastReceiver() {
~>        override fun onReceive(context: Context, intent: Intent) {
            val target = intent.getStringExtra("target") ?: "default"
            BackupWorker.enqueue(context, target)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        registerReceiver(powerReceiver, IntentFilter(Intent.ACTION_POWER_CONNECTED))
    }

    override fun onDestroy() {
        unregisterReceiver(powerReceiver)
        super.onDestroy()
    }
}
