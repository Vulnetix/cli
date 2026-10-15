package com.acme.pair

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class PairingReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (sentFromPackage != "com.acme.companion") return
        val code = intent.getStringExtra("code")
        Pairing.accept(context, code)
    }
}
