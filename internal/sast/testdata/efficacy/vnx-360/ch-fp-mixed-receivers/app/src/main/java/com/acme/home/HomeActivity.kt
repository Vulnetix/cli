package com.acme.home

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.appcompat.app.AppCompatActivity

class HomeActivity : AppCompatActivity() {

    private val batteryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != Intent.ACTION_BATTERY_LOW) return
            pauseSync()
        }
    }

    private val syncReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            refreshList()
        }
    }

    override fun onStart() {
        super.onStart()
        registerReceiver(batteryReceiver, IntentFilter(Intent.ACTION_BATTERY_LOW))
        registerReceiver(syncReceiver, IntentFilter("com.acme.home.SYNC_DONE"))
    }

    private fun pauseSync() {}
    private fun refreshList() {}
}
