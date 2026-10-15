package com.acme.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class StartOnBoot : BroadcastReceiver() {
~>    override fun onReceive(
        context: Context,
        intent: Intent,
    ) {
        val target = intent.getStringExtra("service") ?: "default"
        Launcher.start(context, target)
    }
}
