package com.example.sync

import android.app.Service
import android.content.Intent

class SyncService : Service() {
    fun publish(accountId: String, authToken: String) {
        val update = Intent("com.example.sync.UPDATED")
        update.putExtra("account", accountId)
        update.putExtra("token", authToken)
~>        sendBroadcast(update)
    }

    override fun onBind(intent: Intent?) = null
}
