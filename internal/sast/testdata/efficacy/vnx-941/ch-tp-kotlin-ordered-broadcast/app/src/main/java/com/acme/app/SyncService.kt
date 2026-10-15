package com.acme.app

import android.app.Service
import android.content.Intent

abstract class SyncService : Service() {
    fun publish(account: String) {
        val i = Intent(ACTION_SYNC_DONE)
        i.putExtra("account", account)
~>        sendOrderedBroadcast(i, null)
    }

    companion object {
        const val ACTION_SYNC_DONE = "com.acme.app.SYNC_DONE"
    }
}
